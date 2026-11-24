//! `params` on `run_query` and `explain`, end to end against the real target:
//! each JSON type binds as its SQL type, a param is only ever a value, the
//! guard still reads the SQL alone, and the audit row stores the params.
//! Every call asserts its audit row.

use serde_json::{Value, json};

use crate::common::audit::{assert_audit_outcome, latest_audit};
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mcp::call_tool;

/// A Postgres target the caller may read, and a Redis one it may too: the
/// Redis server is never reached, `params` is refused before any connection.
const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only
  - name: cache
    kind: redis
    host: localhost
    port: 6379
    tls: insecure
    databases:
      - name: "0"
        role: nobody
        password: never-used

permissions:
  - group: engineers
    grants:
      - { server: target, database: app, action: query_read }
      - { server: cache, database: "0", action: query_read }
"#;

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("params-{}", uuid::Uuid::new_v4().simple()),
        email: "params-e2e@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&crate::common::pg_target::config_yaml(YAML), user).await
}

async fn run_query(gw: &LoggedInGateway, sql: &str, params: Value) -> Value {
    let arguments = json!({ "server": "target", "database": "app", "sql": sql, "params": params });
    call_tool(gw, "run_query", arguments).await
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result text: {response}"));
    serde_json::from_str(text).expect("payload is JSON")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn each_json_type_binds_and_the_audit_row_stores_the_params() {
    let gw = boot().await;
    let params = json!([7, "hi", true, 1.5, {"k": "v"}, null, [1, 2]]);
    let resp = run_query(
        &gw,
        "SELECT $1 + 1 AS i, $2 AS t, NOT $3 AS b, $4 * 2 AS f, $5 ->> 'k' AS j, \
         $6::int IS NULL AS n, jsonb_array_length($7) AS len",
        params.clone(),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["rows"][0], json!([8, "hi", false, 3.0, "v", true, 2]));

    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", "typed params").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.params, Some(params));

    // An int8 param compares with an int4 column; a call without params
    // stores none.
    let resp = run_query(
        &gw,
        "SELECT count(*) AS n FROM generate_series(1, 10) AS g WHERE g > $1",
        json!([7]),
    )
    .await;
    assert_eq!(payload(&resp)["rows"][0][0], 3, "{resp}");
    let resp = run_query(&gw, "SELECT 1", json!([])).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", "no params").await;
    assert_eq!(row.params, None);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_param_is_a_value_never_sql() {
    let gw = boot().await;
    for hostile in [
        "1; DROP TABLE audit_calls",
        "' OR '1'='1",
        "$$ ; SELECT pg_terminate_backend(1) $$",
    ] {
        let resp = run_query(&gw, "SELECT $1 AS v", json!([hostile])).await;
        assert_eq!(payload(&resp)["rows"][0][0], hostile, "{resp}");
        let resp = run_query(
            &gw,
            "SELECT count(*) AS n FROM generate_series(1, 3) AS g WHERE g::text = $1",
            json!([hostile]),
        )
        .await;
        assert_eq!(payload(&resp)["rows"][0][0], 0, "{hostile}: {resp}");
        assert_audit_outcome(&gw.state_db, &gw.user_sub, "run_query", "success", hostile).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn the_guard_still_refuses_denied_sql_carrying_params() {
    let gw = boot().await;
    for sql in [
        "DELETE FROM pg_class WHERE oid = $1",
        "SELECT pg_terminate_backend($1)",
    ] {
        let resp = run_query(&gw, sql, json!([1])).await;
        assert_eq!(payload(&resp)["code"], "forbidden_sql", "{sql}: {resp}");
        let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", sql).await;
        assert_eq!(row.outcome, "forbidden_sql");
        assert_eq!(row.params, Some(json!([1])), "{sql}");
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn bad_params_are_invalid_arguments_and_audited() {
    let gw = boot().await;
    let cases = [
        (json!(vec![1; 101]), "at most 100"),
        (json!([u64::MAX]), "integer past int8"),
        (json!(["x".repeat(64 * 1024)]), "at most 65536"),
    ];
    for (params, expected) in cases {
        let resp = run_query(&gw, "SELECT $1", params).await;
        assert_eq!(resp["error"]["code"], -32602, "{resp}");
        let message = resp["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(expected), "{expected}: {message}");
        assert_audit_outcome(
            &gw.state_db,
            &gw.user_sub,
            "run_query",
            "invalid_arguments",
            expected,
        )
        .await;
    }

    let resp = call_tool(
        &gw,
        "run_query",
        json!({ "server": "cache", "database": "0", "sql": "[\"GET\",\"k\"]", "params": [1] }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let message = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("not supported for redis"), "{message}");
    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", "redis params").await;
    assert_eq!(row.outcome, "invalid_arguments");
    assert_eq!(row.db_type.as_deref(), Some("redis"));
}

/// `relacl` is `aclitem[]`, which has no binary form: the read runs a second
/// time with it cast to text, params bound to both attempts — and a `;`
/// followed by a comment still ends the statement the probe nests.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_text_cast_retry_carries_params_and_trailing_comments() {
    let gw = boot().await;
    let resp = run_query(
        &gw,
        "SELECT relname, relacl FROM pg_class WHERE relname = $1",
        json!(["pg_class"]),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert_eq!(payload(&resp)["rows"][0][0], "pg_class");
    assert_audit_outcome(&gw.state_db, &gw.user_sub, "run_query", "success", "recast").await;

    for sql in [
        "SELECT relname, relacl FROM pg_class WHERE relname = 'pg_class'; -- c",
        "SELECT relname, relacl FROM pg_class WHERE relname = 'pg_class' ; /* c */",
    ] {
        let resp = call_tool(
            &gw,
            "run_query",
            json!({ "server": "target", "database": "app", "sql": sql }),
        )
        .await;
        assert_eq!(resp["result"]["isError"], false, "{sql}: {resp}");
        assert_eq!(payload(&resp)["rows"][0][0], "pg_class", "{sql}");
        assert_audit_outcome(&gw.state_db, &gw.user_sub, "run_query", "success", sql).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn explain_binds_params_and_audits_them() {
    let gw = boot().await;
    let arguments = json!({
        "server": "target",
        "database": "app",
        "sql": "SELECT relname FROM pg_class WHERE relname = $1",
        "params": ["pg_class"],
    });
    let resp = call_tool(&gw, "explain", arguments).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert!(body["plan"][0]["Plan"]["Node Type"].is_string(), "{body}");
    assert!(body["summary"]["node_count"].as_u64() >= Some(1), "{body}");
    let row = latest_audit(&gw.state_db, &gw.user_sub, "explain", "explain params").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.params, Some(json!(["pg_class"])));
}
