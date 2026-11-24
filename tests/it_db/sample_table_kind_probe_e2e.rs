//! `sample_table` must not tell an ungranted caller what kind a server is:
//! the `table` rule depends on the kind, so before authz every `table` is
//! held to the loosest rule and the target's own rule applies only once the
//! caller is authorized. A Mongo `system.*` collection is refused
//! `forbidden` after authz. Every call is refused before the target is
//! reached, so the Mongo server is never dialled; the state DB is real.

use std::time::Duration;

use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::config_yaml;

const TOOL: &str = "sample_table";

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
  - name: analytics
    kind: mongo
    description: never reached
    host: analytics.example.invalid
    databases:
      - { name: dw, role: ro, password: dwpw }

permissions:
  - group: pg-readers
    grants:
      - { server: target, database: app, action: query_read }
  - group: mongo-readers
    grants:
      - { server: analytics, database: dw, action: query_read }
"#;

async fn boot(group: &str) -> LoggedInGateway {
    let user = MockUser {
        sub: format!("kindprobe-{}", Uuid::new_v4().simple()),
        email: "kind-probe@example.com".to_string(),
        groups: vec![group.to_string()],
    };
    spawn_logged_in(&config_yaml(YAML), user).await
}

/// The response with the per-call `request_id` removed, and the audit row's
/// outcome and message.
async fn sample(gateway: &LoggedInGateway, server: &str, table: &str) -> (Value, String, String) {
    let database = if server == "analytics" { "dw" } else { "app" };
    let mut response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": TOOL, "arguments":
                { "server": server, "database": database, "table": table } }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    if let Some(text) = response["result"]["content"][0]["text"].as_str() {
        let mut body: Value = serde_json::from_str(text).expect("error body is JSON");
        body.as_object_mut().map(|b| b.remove("request_id"));
        response["result"]["content"][0]["text"] = body;
    }
    let row = latest_audit(&gateway.state_db, &gateway.user_sub, TOOL, table).await;
    assert_eq!(row.server.as_deref(), Some(server), "{table}");
    (
        response,
        row.outcome.to_string(),
        row.error_message.unwrap_or_default(),
    )
}

/// A caller with no grant on the Mongo server gets, for each `table`, the
/// same answer there as for a server that does not exist.
#[tokio::test]
#[serial_test::parallel(world)]
async fn an_ungranted_caller_cannot_tell_a_mongo_server_from_an_unknown_one() {
    let gateway = boot("pg-readers").await;
    for (table, outcome) in [("a-b", "forbidden"), ("a b", "invalid_arguments")] {
        let (mongo, mongo_outcome, mongo_message) = sample(&gateway, "analytics", table).await;
        let (unknown, unknown_outcome, unknown_message) = sample(&gateway, "nope", table).await;
        assert_eq!(mongo, unknown, "{table}");
        assert_eq!(mongo_outcome, outcome, "{table}: {mongo}");
        assert_eq!(unknown_outcome, outcome, "{table}");
        assert_eq!(mongo_message, unknown_message, "{table}");
    }
}

/// Once authorized, the target's own rule applies: a Postgres table must be
/// an identifier, and the message names that rule.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_granted_postgres_table_must_be_an_identifier() {
    let gateway = boot("pg-readers").await;
    let (response, outcome, message) = sample(&gateway, "target", "a-b").await;
    assert_eq!(outcome, "invalid_arguments");
    assert_eq!(response["error"]["code"], -32602, "{response}");
    assert_eq!(message, "`table` must match ^[A-Za-z_][A-Za-z0-9_]*$");
}

/// A Mongo `system.*` collection is server state: `forbidden`, audited,
/// never read.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_mongo_system_collection_is_forbidden() {
    let gateway = boot("mongo-readers").await;
    for table in ["system.profile", "system.views", "system.js"] {
        let (response, outcome, message) = sample(&gateway, "analytics", table).await;
        let body = &response["result"]["content"][0]["text"];
        assert_eq!(body["code"], "forbidden", "{response}");
        assert_eq!(outcome, "forbidden");
        assert_eq!(
            message,
            "system collections are not readable through the gateway"
        );
    }
}
