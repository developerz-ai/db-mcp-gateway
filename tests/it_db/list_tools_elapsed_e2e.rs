//! Every success row carries `elapsed_ms` (spec 07: "wall-clock of the
//! tool's work"), including the tools that never reach a target:
//! `list_servers`, `list_databases`, `get_query_history`.

use std::time::Duration;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};

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
  - group: listers
    grants:
      - { server: target, database: app, action: schema_read }
      - { server: target, database: app, action: history_read }
"#;

async fn call(gw: &LoggedInGateway, tool: &str, arguments: Value) -> Value {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&gw.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn untargeted_success_rows_carry_elapsed_ms() {
    let user = MockUser {
        sub: format!("list-elapsed-{}", uuid::Uuid::new_v4().simple()),
        email: "list-elapsed@example.com".into(),
        groups: vec!["listers".into()],
    };
    let gw = spawn_logged_in(&crate::common::pg_target::config_yaml(YAML), user).await;

    for (tool, arguments) in [
        ("list_servers", json!({})),
        ("list_databases", json!({ "server": "target" })),
        (
            "get_query_history",
            json!({ "server": "target", "database": "app" }),
        ),
    ] {
        let resp = call(&gw, tool, arguments).await;
        assert_eq!(resp["result"]["isError"], false, "{tool}: {resp}");
        let row = latest_audit(&gw.state_db, &gw.user_sub, tool, tool).await;
        assert_eq!(row.outcome, "success", "{tool}");
        assert!(
            row.elapsed_ms.is_some_and(|ms| ms >= 0),
            "{tool}: elapsed_ms {:?}",
            row.elapsed_ms
        );
    }
}
