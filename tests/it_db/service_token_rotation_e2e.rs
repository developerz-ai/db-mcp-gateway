//! A16 (spec 14 §Rotate): `tokens:` lets one service account carry an old and
//! a new token at once. Both authenticate as the same `service:<name>`, so a
//! rotation never renames the audit identity.

use crate::common::audit::latest_audit;
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client};
use reqwest::StatusCode;
use serde_json::json;

/// Synthetic, well-formed fixture tokens (spec 14 shape); never valid anywhere.
const OLD_TOKEN: &str =
    "dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333";
const NEW_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444444";

const YAML: &str = r#"
servers:
  - name: staging
    kind: postgres
    description: rotation e2e
    host: staging.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
permissions:
  - group: svc-rotating
    grants:
      - { server: staging, database: "*", action: query_read }
service_accounts:
  - name: rotating-bot
    group: svc-rotating
    tokens:
      - dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333
      - dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444444
"#;

#[tokio::test]
#[serial_test::parallel(world)]
async fn both_tokens_of_a_rotating_account_audit_as_one_identity() {
    let gw = GatewayBuilder::new(YAML).spawn(state_pool().await).await;
    let client = no_redirect_client();
    let mut rows = Vec::new();
    for (id, token) in [(1, OLD_TOKEN), (2, NEW_TOKEN)] {
        let resp = client
            .post(format!("{}/mcp", gw.url))
            .bearer_auth(token)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": "list_servers", "arguments": {} },
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "token {id} authenticates");
        let row = latest_audit(
            &gw.state_db,
            "service:rotating-bot",
            "list_servers",
            "rotation call",
        )
        .await;
        assert_eq!(row.outcome.to_string(), "success");
        rows.push(row);
    }
    let (old, new) = (&rows[0], &rows[1]);
    assert_ne!(old.id, new.id, "each call is its own audit row");
    assert_eq!(new.user_sub, old.user_sub);
    assert_eq!(new.user_email, "rotating-bot@service-accounts.invalid");
    assert_eq!(new.user_email, old.user_email);
    assert_eq!(new.groups, vec!["svc-rotating".to_string()]);
    assert_eq!(new.groups, old.groups);
}
