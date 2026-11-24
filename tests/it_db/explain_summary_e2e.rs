//! `explain`'s `summary` on plans whose shape the catalog fixes: a bare
//! catalog read is one sequential scan, a filter on its unique name index
//! (with sequential scans off) is none. Every call asserts its audit row.

use serde_json::{Value, json};

use crate::common::audit::assert_audit_outcome;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mcp::call_tool;

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
      - { server: target, database: app, action: query_read }
"#;

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("explain-summary-{}", uuid::Uuid::new_v4().simple()),
        email: "explain-summary@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&crate::common::pg_target::config_yaml(YAML), user).await
}

async fn summary(gw: &LoggedInGateway, sql: &str) -> Value {
    let arguments = json!({ "server": "target", "database": "app", "sql": sql });
    let resp = call_tool(gw, "explain", arguments).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    let body: Value = serde_json::from_str(text).expect("payload is JSON");
    assert_audit_outcome(&gw.state_db, &gw.user_sub, "explain", "success", sql).await;
    let root = &body["plan"][0]["Plan"];
    assert_eq!(body["summary"]["total_cost"], root["Total Cost"], "{body}");
    assert_eq!(
        body["summary"]["plan_rows"].as_f64(),
        root["Plan Rows"].as_f64()
    );
    body["summary"].clone()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_catalog_scan_summarises_as_one_seq_scan() {
    let gw = boot().await;
    let summary = summary(&gw, "SELECT relname FROM pg_class").await;
    assert_eq!(summary["seq_scans"], json!(["pg_class"]), "{summary}");
    assert_eq!(summary["node_count"], 1, "{summary}");
    assert!(summary["total_cost"].as_f64() > Some(0.0), "{summary}");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_join_counts_every_node_and_names_each_seq_scan_once() {
    let gw = boot().await;
    let summary = summary(
        &gw,
        "SELECT a.relname FROM pg_class a CROSS JOIN pg_class b CROSS JOIN pg_namespace n",
    )
    .await;
    let scans = summary["seq_scans"].as_array().expect("seq_scans");
    assert!(scans.contains(&json!("pg_class")), "{summary}");
    assert!(scans.contains(&json!("pg_namespace")), "{summary}");
    assert_eq!(scans.len(), 2, "each relation once: {summary}");
    assert!(summary["node_count"].as_u64() >= Some(5), "{summary}");
}
