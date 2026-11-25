//! The statement bounds over HTTP: past one, `forbidden_sql` and its audit
//! row; at the length cap, an answer and an audit row. Either way the same
//! gateway serves the next call.

use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::config_yaml;

const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }

permissions:
  - group: engineers
    grants:
      - { server: target, database: app, action: query_read }
"#;

const CAP: usize = 64 * 1024;

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("guardbounds-{}", Uuid::new_v4().simple()),
        email: "guard-bounds@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&config_yaml(YAML), user).await
}

/// The tool result: whether it is an error, and its JSON body.
async fn call(gateway: &LoggedInGateway, tool: &str, sql: &str) -> (bool, Value) {
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool,
                        "arguments": { "server": "target", "database": "app", "sql": sql } }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result text: {response}"));
    (
        response["result"]["isError"] == true,
        serde_json::from_str(text).expect("JSON body"),
    )
}

async fn assert_still_serving(gateway: &LoggedInGateway) {
    let (is_error, body) = call(gateway, "run_query", "SELECT 41 + 1 AS n").await;
    assert!(!is_error, "{body}");
    let row = latest_audit(
        &gateway.state_db,
        &gateway.user_sub,
        "run_query",
        "next call",
    )
    .await;
    assert_eq!(row.outcome, "success");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_statement_past_a_bound_is_refused_and_audited_and_the_next_call_runs() {
    let gateway = boot().await;
    let joins = format!("SELECT 1 FROM t{}", " JOIN t".repeat(9000));
    let selects = vec!["SELECT 1"; 2000].join(" UNION ALL ");
    for (sql, names) in [(joins, "512 joins"), (selects, "1024 SELECTs")] {
        for tool in ["run_query", "explain"] {
            let (is_error, body) = call(&gateway, tool, &sql).await;
            assert!(is_error, "{body}");
            assert_eq!(body["code"], "forbidden_sql", "{body}");
            let message = body["message"].as_str().unwrap_or_default();
            assert!(message.contains(names), "{message}");
            let row = latest_audit(&gateway.state_db, &gateway.user_sub, tool, names).await;
            assert_eq!(row.outcome, "forbidden_sql");
            assert_eq!(body["request_id"].as_str(), Some(row.request_id.as_str()));
            assert_still_serving(&gateway).await;
        }
    }
}

/// Long operator chains pass the guard; the target decides.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_chain_at_the_length_cap_is_answered_and_audited_and_the_next_call_runs() {
    let gateway = boot().await;
    for part in ["+1", "||1", " AND true", "::int", "[1]"] {
        let sql = format!("SELECT 1{}", part.repeat((CAP - 8) / part.len()));
        for tool in ["run_query", "explain"] {
            let (_, body) = call(&gateway, tool, &sql).await;
            let row = latest_audit(&gateway.state_db, &gateway.user_sub, tool, part).await;
            if let Some(code) = body["code"].as_str() {
                assert_eq!(row.outcome, code, "{part:?}: {}", body["message"]);
            }
            assert_still_serving(&gateway).await;
        }
    }
}
