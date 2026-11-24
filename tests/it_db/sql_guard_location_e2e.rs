//! An unparseable statement over HTTP: `forbidden_sql` that says where the
//! parser stopped (line and column, never the parser's quote of the text),
//! and its audit row.

use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::spawn_logged_in;
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

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_parse_error_names_its_line_and_column() {
    let gateway = spawn_logged_in(
        &config_yaml(YAML),
        MockUser {
            sub: format!("guardloc-{}", Uuid::new_v4().simple()),
            email: "guard-location@example.com".to_string(),
            groups: vec!["engineers".to_string()],
        },
    )
    .await;
    let sql = "SELECT 1\nFROM t WHERE 'secret' = = 1";
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "run_query",
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
        .expect("tool error text");
    let body: Value = serde_json::from_str(text).expect("JSON body");
    assert_eq!(body["code"], "forbidden_sql", "{body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(message.contains("at line 2, column 25"), "{message}");
    assert!(!message.contains("secret"), "{message}");
    assert_eq!(body["location"], json!({"line": 2, "column": 25}), "{body}");

    let row = latest_audit(&gateway.state_db, &gateway.user_sub, "run_query", sql).await;
    assert_eq!(row.outcome, "forbidden_sql");
    assert!(
        row.error_message
            .as_deref()
            .is_some_and(|m| m.contains("at line 2, column 25")),
        "{:?}",
        row.error_message
    );
}
