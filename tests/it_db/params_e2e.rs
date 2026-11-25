//! `params` on `run_query` and `explain`, end to end against the real target:
//! each JSON type binds as its SQL type, a param is only ever a value, the
//! guard still reads the SQL alone, and the audit row stores the params.
//! Every call asserts its audit row.

use std::time::Duration;

use serde_json::{Value, json};

use crate::common::audit::calls_for_request;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;

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

/// One tool call's JSON-RPC response and the gateway `request_id` the
/// `x-request-id` header names, the key of that call's own audit row.
struct Called {
    request_id: String,
    response: Value,
}

async fn call_tool(gw: &LoggedInGateway, tool: &str, arguments: Value) -> Called {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&gw.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }))
        .send()
        .await
        .expect("gateway answers");
    let request_id = http.headers()["x-request-id"]
        .to_str()
        .expect("x-request-id is text")
        .to_owned();
    let response = http.json().await.expect("JSON-RPC body");
    Called {
        request_id,
        response,
    }
}

async fn run_query(gw: &LoggedInGateway, sql: &str, params: Value) -> Called {
    let arguments = json!({ "server": "target", "database": "app", "sql": sql, "params": params });
    call_tool(gw, "run_query", arguments).await
}

/// The one audit row of `called`: `(outcome, params, db_type)`. Keyed by its
/// own `request_id`, so an earlier call's row can never stand in for it.
async fn audit_of(
    gw: &LoggedInGateway,
    called: &Called,
) -> (String, Option<Value>, Option<String>) {
    let rows: Vec<(String, Option<Value>, Option<String>)> =
        sqlx::query_as("SELECT outcome, params, db_type FROM audit_calls WHERE request_id = $1")
            .bind(&called.request_id)
            .fetch_all(&gw.state_db)
            .await
            .expect("audit_calls lookup query runs");
    assert_eq!(rows.len(), 1, "one audit row per call: {rows:?}");
    assert_eq!(
        calls_for_request(&gw.state_db, &called.request_id)
            .await
            .len(),
        1
    );
    rows.into_iter().next().expect("one row")
}

fn payload(called: &Called) -> Value {
    let response = &called.response;
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
    assert_eq!(
        resp.response["result"]["isError"], false,
        "{}",
        resp.response
    );
    let body = payload(&resp);
    assert_eq!(body["rows"][0], json!([8, "hi", false, 3.0, "v", true, 2]));
    let (outcome, stored, _) = audit_of(&gw, &resp).await;
    assert_eq!(outcome, "success");
    assert_eq!(stored, Some(params));

    // An int8 param compares with an int4 column; a call without params
    // stores none.
    let resp = run_query(
        &gw,
        "SELECT count(*) AS n FROM generate_series(1, 10) AS g WHERE g > $1",
        json!([7]),
    )
    .await;
    assert_eq!(payload(&resp)["rows"][0][0], 3, "{}", resp.response);
    assert_eq!(audit_of(&gw, &resp).await.0, "success");
    let resp = run_query(&gw, "SELECT 1", json!([])).await;
    assert_eq!(
        resp.response["result"]["isError"], false,
        "{}",
        resp.response
    );
    let (outcome, stored, _) = audit_of(&gw, &resp).await;
    assert_eq!(outcome, "success");
    assert_eq!(stored, None);
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
        assert_eq!(payload(&resp)["rows"][0][0], hostile, "{}", resp.response);
        assert_eq!(audit_of(&gw, &resp).await.0, "success", "{hostile}");
        let resp = run_query(
            &gw,
            "SELECT count(*) AS n FROM generate_series(1, 3) AS g WHERE g::text = $1",
            json!([hostile]),
        )
        .await;
        assert_eq!(
            payload(&resp)["rows"][0][0],
            0,
            "{hostile}: {}",
            resp.response
        );
        assert_eq!(audit_of(&gw, &resp).await.0, "success", "{hostile}");
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
        assert_eq!(
            payload(&resp)["code"],
            "forbidden_sql",
            "{sql}: {}",
            resp.response
        );
        let (outcome, stored, _) = audit_of(&gw, &resp).await;
        assert_eq!(outcome, "forbidden_sql");
        assert_eq!(stored, Some(json!([1])), "{sql}");
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
        assert_eq!(resp.response["error"]["code"], -32602, "{}", resp.response);
        let message = resp.response["error"]["message"]
            .as_str()
            .unwrap_or_default();
        assert!(message.contains(expected), "{expected}: {message}");
        assert_eq!(
            audit_of(&gw, &resp).await.0,
            "invalid_arguments",
            "{expected}"
        );
    }

    let resp = call_tool(
        &gw,
        "run_query",
        json!({ "server": "cache", "database": "0", "sql": "[\"GET\",\"k\"]", "params": [1] }),
    )
    .await;
    assert_eq!(resp.response["error"]["code"], -32602, "{}", resp.response);
    let message = resp.response["error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(message.contains("not supported for redis"), "{message}");
    let (outcome, _, db_type) = audit_of(&gw, &resp).await;
    assert_eq!(outcome, "invalid_arguments");
    assert_eq!(db_type.as_deref(), Some("redis"));
}

/// `relacl` is `aclitem[]`, which has no binary form: the read runs with
/// it cast to text, params bound — and a `;` followed by a comment still
/// ends the statement the cast nests.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_text_cast_carries_params_and_trailing_comments() {
    let gw = boot().await;
    let resp = run_query(
        &gw,
        "SELECT relname, relacl FROM pg_class WHERE relname = $1",
        json!(["pg_class"]),
    )
    .await;
    assert_eq!(
        resp.response["result"]["isError"], false,
        "{}",
        resp.response
    );
    assert_eq!(payload(&resp)["rows"][0][0], "pg_class");
    assert_eq!(audit_of(&gw, &resp).await.0, "success");

    for sql in [
        "SELECT relname, relacl FROM pg_class WHERE relname = 'pg_class'; -- c",
        "SELECT relname, relacl FROM pg_class WHERE relname = 'pg_class' ; /* c */",
        "; SELECT relname, relacl FROM pg_class WHERE relname = 'pg_class'",
    ] {
        let resp = call_tool(
            &gw,
            "run_query",
            json!({ "server": "target", "database": "app", "sql": sql }),
        )
        .await;
        assert_eq!(
            resp.response["result"]["isError"], false,
            "{sql}: {}",
            resp.response
        );
        assert_eq!(payload(&resp)["rows"][0][0], "pg_class", "{sql}");
        assert_eq!(audit_of(&gw, &resp).await.0, "success", "{sql}");
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
    assert_eq!(
        resp.response["result"]["isError"], false,
        "{}",
        resp.response
    );
    let body = payload(&resp);
    assert!(body["plan"][0]["Plan"]["Node Type"].is_string(), "{body}");
    assert!(body["summary"]["node_count"].as_u64() >= Some(1), "{body}");
    let (outcome, stored, _) = audit_of(&gw, &resp).await;
    assert_eq!(outcome, "success");
    assert_eq!(stored, Some(json!(["pg_class"])));
}

/// A zero-row read still names its columns and types, even when a
/// placeholder's type comes only from its bound param.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_zero_row_read_with_params_keeps_its_columns() {
    let gw = boot().await;
    let resp = run_query(
        &gw,
        "SELECT $1 AS v, $2 IS NULL AS missing WHERE false",
        json!([7, "x"]),
    )
    .await;
    assert_eq!(
        resp.response["result"]["isError"], false,
        "{}",
        resp.response
    );
    let body = payload(&resp);
    assert_eq!(body["rows"], json!([]), "{body}");
    assert_eq!(body["columns"], json!(["v", "missing"]), "{body}");
    assert_eq!(body["column_types"], json!(["INT8", "BOOL"]), "{body}");
    assert_eq!(audit_of(&gw, &resp).await.0, "success");
}

/// The intent row keeps the params too, so a call the reaper later marks
/// `abandoned` still records what it bound; a call without params stores
/// none there either.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_intent_row_stores_the_params() {
    let gw = boot().await;
    let intent_params = |called: &Called| {
        let request_id = called.request_id.clone();
        let pool = gw.state_db.clone();
        async move {
            sqlx::query_scalar::<_, Option<Value>>(
                "SELECT params FROM audit_call_intents WHERE request_id = $1",
            )
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("intent row written")
        }
    };
    let with = run_query(&gw, "SELECT $1::int8 + 1 AS n", json!([41])).await;
    assert_eq!(payload(&with)["rows"][0][0], 42, "{}", with.response);
    assert_eq!(audit_of(&gw, &with).await.0, "success");
    assert_eq!(intent_params(&with).await, Some(json!([41])));

    let explained = call_tool(
        &gw,
        "explain",
        json!({ "server": "target", "database": "app",
                "sql": "SELECT $1::text AS t", "params": ["x"] }),
    )
    .await;
    assert_eq!(audit_of(&gw, &explained).await.0, "success");
    assert_eq!(intent_params(&explained).await, Some(json!(["x"])));

    let without = run_query(&gw, "SELECT 1", json!([])).await;
    assert_eq!(audit_of(&gw, &without).await.0, "success");
    assert_eq!(intent_params(&without).await, None);
}
