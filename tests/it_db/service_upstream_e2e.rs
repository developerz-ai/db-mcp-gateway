//! Upstream attribution for service tokens (plan 101 slice 12, spec 14):
//! `x-dbmcp-run-id` / `x-dbmcp-on-behalf-of` land in the audit row as
//! CLAIMED values, `require_upstream` refuses calls without them (audited
//! `invalid_arguments`), an SSO session's headers are ignored, and
//! `get_query_history` for a run sees only that run.
//!
//! State DB only — no tool here reaches a target database.

use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};
use uuid::Uuid;

const TOKEN: &str = "dbmcp_svc_3333333333333333333333333333333333333333333333333333333333333333";
const STRICT_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444444";

/// Two service accounts with unique names (tests share the state DB): a
/// lenient one and one with `require_upstream`. The logged-in human is in
/// `engineers`.
fn yaml(account: &str) -> String {
    format!(
        r#"
servers:
  - name: staging
    kind: postgres
    description: E2E staging
    host: staging.example.invalid
    databases:
      - {{ name: app, role: ro, password: stagingpw }}

permissions:
  - group: engineers
    grants:
      - {{ server: staging, database: app, action: query_read }}
  - group: svc-agents
    grants:
      - {{ server: staging, database: app, action: query_read }}
      - {{ server: staging, database: app, action: history_read }}

service_accounts:
  - name: {account}
    group: svc-agents
    token: {TOKEN}
  - name: {account}-strict
    group: svc-agents
    token: {STRICT_TOKEN}
    require_upstream: true
"#
    )
}

async fn boot() -> (LoggedInGateway, String) {
    let account = format!("fleet-{}", Uuid::new_v4().simple());
    let human = MockUser {
        sub: format!("human-{}", Uuid::new_v4().simple()),
        email: "human@example.com".into(),
        groups: vec!["engineers".into()],
    };
    (spawn_logged_in(&yaml(&account), human).await, account)
}

async fn call(
    gw: &LoggedInGateway,
    bearer: &str,
    headers: &[(&str, &str)],
    tool: &str,
    args: Value,
) -> Value {
    let mut request = reqwest::Client::new()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        }));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    response.json().await.unwrap()
}

const CLAIM: [(&str, &str); 2] = [
    ("x-dbmcp-run-id", "run-42"),
    ("x-dbmcp-on-behalf-of", "alice@example.com"),
];

#[tokio::test]
#[serial_test::parallel(world)]
async fn claimed_upstream_lands_in_the_audit_row() {
    let (gw, account) = boot().await;
    let subject = format!("service:{account}");

    let resp = call(&gw, TOKEN, &CLAIM, "list_servers", json!({})).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");

    let row = latest_audit(&gw.state_db, &subject, "list_servers", "claimed upstream").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.user_sub, subject, "the audit subject stays the service");
    assert_eq!(row.upstream_run_id.as_deref(), Some("run-42"));
    assert_eq!(row.upstream_actor.as_deref(), Some("alice@example.com"));
    delete_audit_calls(&gw.state_db, &subject).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn malformed_upstream_header_is_refused_and_audited() {
    let (gw, account) = boot().await;
    let subject = format!("service:{account}");

    let bad = [("x-dbmcp-run-id", "run 42; drop")];
    let resp = call(&gw, TOKEN, &bad, "list_servers", json!({})).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");

    let row = latest_audit(&gw.state_db, &subject, "list_servers", "malformed upstream").await;
    assert_eq!(row.outcome, "invalid_arguments");
    assert_eq!(row.upstream_run_id, None, "a refused claim is not recorded");
    delete_audit_calls(&gw.state_db, &subject).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn require_upstream_refuses_calls_without_both_headers() {
    let (gw, account) = boot().await;
    let subject = format!("service:{account}-strict");

    let run_only = [("x-dbmcp-run-id", "run-42")];
    let resp = call(&gw, STRICT_TOKEN, &run_only, "list_servers", json!({})).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let row = latest_audit(&gw.state_db, &subject, "list_servers", "require_upstream").await;
    assert_eq!(row.outcome, "invalid_arguments");

    let resp = call(&gw, STRICT_TOKEN, &CLAIM, "list_servers", json!({})).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    delete_audit_calls(&gw.state_db, &subject).await;
}

/// An SSO session's identity is verified; claimed headers on it are ignored,
/// never stored.
#[tokio::test]
#[serial_test::parallel(world)]
async fn sso_session_upstream_headers_are_ignored() {
    let (gw, _) = boot().await;

    let resp = call(&gw, &gw.bearer, &CLAIM, "list_servers", json!({})).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");

    let row = latest_audit(&gw.state_db, &gw.user_sub, "list_servers", "sso upstream").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.upstream_run_id, None);
    assert_eq!(row.upstream_actor, None);
    delete_audit_calls(&gw.state_db, &gw.user_sub).await;
}

/// Agents sharing one token read only their own run's history.
#[tokio::test]
#[serial_test::parallel(world)]
async fn history_is_filtered_by_the_claimed_run() {
    let (gw, account) = boot().await;
    let subject = format!("service:{account}");
    for run in ["run-42", "run-other"] {
        sqlx::query(
            "INSERT INTO audit_calls \
             (id, request_id, user_sub, user_email, tool, server_name, database_name, sql, \
              outcome, upstream_run_id) \
             VALUES (gen_random_uuid(), gen_random_uuid()::text, $1, 'svc@x.invalid', \
                     'run_query', 'staging', 'app', $2, 'success', $3)",
        )
        .bind(&subject)
        .bind(format!("SELECT '{run}'"))
        .bind(run)
        .execute(&gw.state_db)
        .await
        .expect("seed history row");
    }

    let args = json!({ "server": "staging", "database": "app" });
    let resp = call(&gw, TOKEN, &CLAIM, "get_query_history", args).await;
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("payload");
    let body: Value = serde_json::from_str(text).unwrap();
    let sqls: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["sql"].as_str())
        .collect();
    assert_eq!(sqls, vec!["SELECT 'run-42'"], "{body}");

    let row = latest_audit(&gw.state_db, &subject, "get_query_history", "history run").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.upstream_run_id.as_deref(), Some("run-42"));
    delete_audit_calls(&gw.state_db, &subject).await;
}
