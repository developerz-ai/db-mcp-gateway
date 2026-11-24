//! `run_query` and `explain` over HTTP for the guard's refusals: text
//! Postgres tokenizes differently, calls in attribute notation, relations
//! showing other sessions' statements, and the SQL-running, network and
//! replication function families. Each answers `forbidden_sql` before the
//! target is touched, and each leaves its audit row.

use std::time::Duration;

use serde_json::{Value, json};

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
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: engineers
    grants:
      - server: target
        database: app
        action: query_read
"#;

/// `(sql, what the refusal message names)`.
const REFUSED: &[(&str, &str)] = &[
    (
        "SELECT 1 >--'\n 2, pg_notify($$jobs$$, $$x$$)--'",
        "put a space",
    ),
    (
        "SELECT E'a'\n'\\' , ' , pg_notify($$j$$, $$x$$) -- '",
        "join them with ||",
    ),
    (
        "SELECT X'\\'' , pg_notify('a', 'b') , X'\\''",
        "different tokens",
    ),
    (
        "SELECT (pid).pg_terminate_backend FROM pg_locks",
        "pg_terminate_backend",
    ),
    ("SELECT ('select 1'::text).ts_stat", "ts_stat"),
    ("SELECT r.http FROM (SELECT 'GET', 'http://x') r", "`http`"),
    ("SELECT query FROM pg_stat_activity", "db_activity"),
    (
        "SELECT * FROM ONLY pg_catalog.pg_stat_statements",
        "db_activity",
    ),
    (
        "SELECT statement FROM pg_prepared_statements",
        "db_activity",
    ),
    (
        "SELECT * FROM pg_stat_get_activity(NULL)",
        "pg_stat_get_activity",
    ),
    ("SELECT * FROM crosstab('select 1, 2, 3')", "crosstab*"),
    (
        "SELECT * FROM xpath_table('k', 'd', 't', '/a', 'true')",
        "xpath_table",
    ),
    ("SELECT http_get('http://169.254.169.254/')", "http_get"),
    ("SELECT aws_lambda.invoke('fn', '{}'::json)", "invoke"),
    (
        "SELECT aws_s3.query_export_to_s3('select 1', 'uri')",
        "query_export_to_s3",
    ),
    (
        "SELECT * FROM pg_logical_slot_get_changes('s', NULL, NULL)",
        "pg_logical_slot_*",
    ),
    (
        "SELECT pg_replication_slot_advance('s', '0/1')",
        "pg_replication_slot_advance",
    ),
    (
        "SELECT pg_drop_replication_slot('s')",
        "pg_drop_replication_slot",
    ),
    (
        "SELECT pg_create_physical_replication_slot('s')",
        "pg_create_*",
    ),
    ("SELECT pg_stat_reset()", "pg_stat_reset*"),
];

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "guard-e2e@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&config_yaml(YAML), user).await
}

async fn call_tool(gateway: &LoggedInGateway, tool: &str, sql: &str) -> Value {
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client builds")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": { "server": "target", "database": "app", "sql": sql }
            }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    assert_eq!(response["result"]["isError"], true, "{sql:?}: {response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("error payload is text content");
    serde_json::from_str(text).expect("error payload is JSON")
}

/// The refusal's own audit row: `forbidden_sql`, keyed by the request id
/// the error body carries.
async fn assert_refused_and_audited(gateway: &LoggedInGateway, tool: &str, sql: &str, names: &str) {
    let body = call_tool(gateway, tool, sql).await;
    assert_eq!(body["code"], "forbidden_sql", "{sql:?}: {body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(message.contains(names), "{sql:?}: {message}");

    let row = latest_audit(&gateway.state_db, &gateway.user_sub, tool, sql).await;
    assert_eq!(row.outcome, "forbidden_sql", "{sql:?}");
    assert_eq!(
        body["request_id"].as_str(),
        Some(row.request_id.as_str()),
        "{sql:?}: the audit row is this request's"
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn run_query_refuses_each_shape_and_audits_it() {
    let gateway = boot().await;
    for (sql, names) in REFUSED {
        assert_refused_and_audited(&gateway, "run_query", sql, names).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn explain_refuses_each_shape_and_audits_it() {
    let gateway = boot().await;
    for (sql, names) in REFUSED {
        assert_refused_and_audited(&gateway, "explain", sql, names).await;
    }
}
