//! `describe_schema` honours `require_reason` like every other tool that
//! reaches the target: no reason → `reason_required`, audited, catalog never
//! read; with one → success, and the reason lands in the audit row.
//!
//! Real Postgres throughout (`bin/dev up` → state DB :5435, target DB :5434).

use crate::common;
use std::time::Duration;

use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};

const TOOL: &str = "describe_schema";

const E2E_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only
        description: Local target-db

permissions:
  - group: reason-required
    grants:
      - server: target
        database: app
        action: schema_read
        constraints:
          require_reason: true
"#;

async fn boot_gateway() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "describe-reason-e2e@example.com".to_string(),
        groups: vec!["reason-required".to_string()],
    };
    spawn_logged_in(E2E_YAML, user).await
}

async fn call(booted: &LoggedInGateway, arguments: Value) -> Value {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", booted.url))
        .bearer_auth(&booted.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": TOOL, "arguments": arguments }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

#[tokio::test]
async fn require_reason_grant_blocks_describe_schema_without_reason() {
    let booted = boot_gateway().await;

    let resp = call(&booted, json!({ "server": "target", "database": "app" })).await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(payload(&resp)["code"], "reason_required", "{resp}");
    let row =
        common::audit::latest_audit(&booted.state_db, &booted.user_sub, TOOL, "no reason").await;
    assert_eq!(row.outcome, "reason_required");
    assert_eq!(row.reason, None);

    let resp = call(
        &booted,
        json!({ "server": "target", "database": "app", "reason": "" }),
    )
    .await;
    assert_eq!(payload(&resp)["code"], "reason_required", "{resp}");

    let resp = call(
        &booted,
        json!({ "server": "target", "database": "app", "reason": "OPS-7 schema review" }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert!(payload(&resp)["tables"].is_array(), "{resp}");
    let row =
        common::audit::latest_audit(&booted.state_db, &booted.user_sub, TOOL, "with reason").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.reason.as_deref(), Some("OPS-7 schema review"));

    common::cleanup::delete_audit_calls(&booted.state_db, &booted.user_sub).await;
}
