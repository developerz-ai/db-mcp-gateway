//! Discovery in one call (plan 101 slice 06, M9–M11): `list_servers` inlines
//! databases, `list_databases` without `server` spans every visible server,
//! each database reports what the caller may do there, and `whoami` reports
//! the caller's own identity and grants (`whoami_e2e`, which shares this
//! fixture). All over real HTTP, each call's audit row asserted.
//!
//! Every target host is unresolvable (`.invalid`): none of these tools may
//! reach a target, so a success here also proves no target call was made.

use std::time::Duration;

use crate::common::audit::{assert_audit_outcome, latest_audit};
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};

/// Fixture service token, never valid anywhere else.
pub(super) const SVC_TOKEN: &str =
    "dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333";

const YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: Prod
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2, description: Main app }
      - { name: billing, role: ro, password: billing_pw }
      - name: sandbox
        role: sandbox_ro
        password: sandbox_pw
        write_role: sandbox_rw
        write_password: sandbox_rw_pw
  - name: secret
    kind: postgres
    description: Nobody here is granted this
    host: secret.example.invalid
    databases:
      - { name: vault, role: ro, password: vault_pw }
  - name: docs
    kind: mongo
    description: Documents
    host: docs.example.invalid
    databases:
      - { name: content, role: ro, password: docs_pw }

permissions:
  - group: discoverers
    grants:
      - server: prod
        database: app
        action: query_read
        constraints: { row_limit: 250, statement_timeout_ms: 4000, require_reason: true }
      - { server: prod, database: sandbox, action: query_write }
      - { server: prod, database: billing, action: history_read }
      - { server: docs, database: "*", action: schema_read }
  - group: svc-discovery
    grants:
      - { server: docs, database: content, action: query_read }

service_accounts:
  - name: discovery-bot
    group: svc-discovery
    token: dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333
"#;

pub(super) async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("discovery-{}", uuid::Uuid::new_v4().simple()),
        email: "discovery@example.com".into(),
        groups: vec!["discoverers".into()],
    };
    spawn_logged_in(YAML, user).await
}

/// `tools/call` → the JSON-RPC envelope.
pub(super) async fn call(
    gw: &LoggedInGateway,
    bearer: &str,
    tool: &str,
    arguments: Option<Value>,
) -> Value {
    let mut params = json!({ "name": tool });
    if let Some(arguments) = arguments {
        params["arguments"] = arguments;
    }
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(bearer)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

pub(super) fn payload(envelope: &Value) -> Value {
    assert_eq!(envelope["result"]["isError"], false, "{envelope}");
    let text = envelope["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

pub(super) fn assert_no_credentials(envelope: &Value) {
    let text = envelope.to_string();
    for secret in [
        "hunter2",
        "billing_pw",
        "sandbox_pw",
        "sandbox_rw",
        "vault_pw",
        "docs_pw",
        "example.invalid",
    ] {
        assert!(!text.contains(secret), "leaked {secret}: {text}");
    }
}

pub(super) fn database_ids(databases: &Value) -> Vec<String> {
    databases
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            format!(
                "{}/{}",
                d["server"].as_str().unwrap(),
                d["name"].as_str().unwrap()
            )
        })
        .collect()
}

/// M9: one `list_databases` with no arguments at all spans every visible
/// server; a database outside the caller's grants never appears, nor does a
/// `history_read`-only one.
#[tokio::test]
#[serial_test::parallel(world)]
async fn list_databases_without_server_spans_visible_servers() {
    let gw = boot().await;
    let envelope = call(&gw, &gw.bearer, "list_databases", None).await;
    assert_no_credentials(&envelope);
    let body = payload(&envelope);
    assert_eq!(
        database_ids(&body["databases"]),
        vec!["prod/app", "prod/sandbox", "docs/content"]
    );
    let row = latest_audit(&gw.state_db, &gw.user_sub, "list_databases", "all").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.server, None);
    assert_eq!(row.row_count, Some(3));
}

/// M10: the per-database fields, as the grant's tools enforce them.
#[tokio::test]
#[serial_test::parallel(world)]
async fn list_databases_reports_effective_grant_fields() {
    let gw = boot().await;
    let body = payload(
        &call(
            &gw,
            &gw.bearer,
            "list_databases",
            Some(json!({ "server": "prod" })),
        )
        .await,
    );
    let databases = body["databases"].as_array().unwrap();
    let app = &databases[0];
    assert_eq!(app["name"], "app");
    assert_eq!(app["description"], "Main app");
    assert_eq!(app["kind"], "postgres");
    assert_eq!(app["actions"], json!(["schema_read", "query_read"]));
    assert_eq!(app["writes"], false);
    let query = &app["limits"][1];
    assert_eq!(query["action"], "query_read");
    assert_eq!(query["require_reason"], true);
    assert_eq!(query["row_limit"], 250);
    assert_eq!(query["statement_timeout_ms"], 4000);
    assert!(
        app["tools"]
            .as_array()
            .unwrap()
            .contains(&json!("run_query"))
    );

    let sandbox = &databases[1];
    assert_eq!(sandbox["name"], "sandbox");
    assert_eq!(sandbox["writes"], true);
    assert_eq!(sandbox["limits"][1]["row_limit"], 100_000);
    assert_eq!(sandbox["limits"][1]["statement_timeout_ms"], 30_000);

    assert_audit_outcome(
        &gw.state_db,
        &gw.user_sub,
        "list_databases",
        "success",
        "prod",
    )
    .await;
}

/// A server with no grant — or no server at all — is `forbidden` with one
/// message, and audited as such.
#[tokio::test]
#[serial_test::parallel(world)]
async fn list_databases_forbidden_for_ungranted_and_unknown_servers() {
    let gw = boot().await;
    let mut messages = Vec::new();
    for server in ["secret", "no-such-server"] {
        let envelope = call(
            &gw,
            &gw.bearer,
            "list_databases",
            Some(json!({ "server": server })),
        )
        .await;
        assert_eq!(envelope["result"]["isError"], true, "{envelope}");
        let error: Value =
            serde_json::from_str(envelope["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(error["code"], "forbidden");
        messages.push(error["message"].clone());
        assert_audit_outcome(
            &gw.state_db,
            &gw.user_sub,
            "list_databases",
            "forbidden",
            server,
        )
        .await;
    }
    assert_eq!(messages[0], messages[1]);
}

/// M9: `list_servers` inlines each visible server's databases and hides the
/// ungranted server entirely.
#[tokio::test]
#[serial_test::parallel(world)]
async fn list_servers_inlines_visible_databases() {
    let gw = boot().await;
    let envelope = call(&gw, &gw.bearer, "list_servers", Some(json!({}))).await;
    assert_no_credentials(&envelope);
    let body = payload(&envelope);
    let servers = body["servers"].as_array().unwrap();
    let names: Vec<&str> = servers
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["prod", "docs"]);
    assert_eq!(
        database_ids(&servers[0]["databases"]),
        vec!["prod/app", "prod/sandbox"]
    );
    assert_eq!(
        servers[1]["databases"][0]["tools"],
        json!(["describe_schema"])
    );
    assert_audit_outcome(
        &gw.state_db,
        &gw.user_sub,
        "list_servers",
        "success",
        "inline",
    )
    .await;
}
