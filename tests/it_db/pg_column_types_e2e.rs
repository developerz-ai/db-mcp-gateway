//! `run_query` over HTTP names each column's type beside its name — for a
//! result with rows and for one with none — and leaves its audit row.

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

async fn run_query(gateway: &LoggedInGateway, sql: &str) -> Value {
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
    assert_eq!(response["result"]["isError"], false, "{response}");
    let row = latest_audit(&gateway.state_db, &gateway.user_sub, "run_query", sql).await;
    assert_eq!(row.outcome, "success");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    serde_json::from_str(text).expect("JSON payload")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_result_names_its_column_types() {
    let gateway = spawn_logged_in(
        &config_yaml(YAML),
        MockUser {
            sub: format!("coltypes-{}", Uuid::new_v4().simple()),
            email: "column-types@example.com".to_string(),
            groups: vec!["engineers".to_string()],
        },
    )
    .await;
    let sql = "SELECT 1::int4 AS n, 'x'::text AS t, now() AS at, ARRAY[1]::int8[] AS a";
    let rows = run_query(&gateway, sql).await;
    assert_eq!(rows["columns"], json!(["n", "t", "at", "a"]));
    assert_eq!(
        rows["column_types"],
        json!(["INT4", "TEXT", "TIMESTAMPTZ", "INT8[]"])
    );

    let empty = run_query(&gateway, "SELECT 1::int2 AS n WHERE false").await;
    assert_eq!(empty["columns"], json!(["n"]));
    assert_eq!(empty["column_types"], json!(["INT2"]));
}
