//! End-to-end service-token tests (issue #185, spec 14): a headless client
//! authenticates with a static bearer from `service_accounts:` — no browser
//! SSO — carrying its own permissions group and audit identity.
//!
//! Boots the same mock-OIDC harness as `auth_e2e.rs` (issue #9 pattern) so
//! both credential kinds coexist on one gateway: the human login flow must
//! keep working unchanged next to the static tokens.
//!
//! Requires a running state Postgres (`bin/dev up`); see CLAUDE.md.

use std::sync::Arc;

use crate::common::audit::latest_audit;
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client};
use crate::common::idp::{MockUser, spawn_mock_idp};
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::state::permissions::{
    DbType, GrantAction, GrantTarget, PermissionsRepo, PermissionsSeed,
};
use serde_json::{Value, json};

/// Well-formed (`dbmcp_svc_` + 64 body chars) but obviously synthetic fixture
/// tokens — the same role `hunter2` plays for DB passwords elsewhere in the
/// test suite. Never valid anywhere else.
const CI_BOT_TOKEN: &str =
    "dbmcp_svc_1111111111111111111111111111111111111111111111111111111111111111";
const ANALYTICS_BOT_TOKEN: &str =
    "dbmcp_svc_2222222222222222222222222222222222222222222222222222222222222222";
/// Correct shape, never configured: must fall through to the JWT path and 401.
const UNCONFIGURED_TOKEN: &str =
    "dbmcp_svc_9999999999999999999999999999999999999999999999999999999999999999";

/// `ci-bot` (group `svc-ci`) can read `staging` only; `analytics-bot`
/// (group `svc-analytics`) is recognized but granted nothing. `engineers`
/// is the human group, granted `prod` — the two identity kinds must not
/// leak into each other. `admin` is enabled to prove a service token never
/// reaches `/admin/*`.
const E2E_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: E2E prod
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
  - name: staging
    kind: postgres
    description: E2E staging
    host: staging.example.invalid
    databases:
      - { name: app, role: ro, password: stagingpw }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: query_read }
  - group: svc-ci
    grants:
      - { server: staging, database: "*", action: query_read }
  - group: svc-analytics
    grants: []

service_accounts:
  - name: ci-bot
    group: svc-ci
    token: dbmcp_svc_1111111111111111111111111111111111111111111111111111111111111111
  - name: analytics-bot
    group: svc-analytics
    token: dbmcp_svc_2222222222222222222222222222222222222222222222222222222222222222

admin:
  enabled: true
  group: admins
"#;

struct BootedGateway {
    url: String,
    client: reqwest::Client,
    state_db: sqlx::PgPool,
}

/// One gateway with everything wired: mock IdP (human path), two service
/// accounts (headless path), admin surface mounted (must stay human-only).
async fn boot_gateway() -> BootedGateway {
    let pool = state_pool().await;

    // The human login flow needs an IdP even though the service-token tests
    // never drive it; same mock as auth_e2e.
    let user = MockUser {
        sub: format!("human-{}", uuid::Uuid::new_v4().simple()),
        email: "human@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let gw = GatewayBuilder::new(E2E_YAML)
        .idp(&idp)
        .repo(repo)
        .spawn(pool)
        .await;
    BootedGateway {
        url: gw.url,
        client: no_redirect_client(),
        state_db: gw.state_db,
    }
}

/// `tools/call` with an optional bearer. Returns the raw HTTP response so
/// both the 401 contract and the JSON-RPC body are assertable.
async fn call_tool(
    gw: &BootedGateway,
    bearer: Option<&str>,
    id: u32,
    tool: &str,
    args: Value,
) -> reqwest::Response {
    let mut request = gw.client.post(format!("{}/mcp", gw.url)).json(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": args }
    }));
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    request.send().await.unwrap()
}

/// The JSON-stringified payload inside a tool response's text content.
async fn tool_payload(response: reqwest::Response) -> Value {
    let envelope: Value = response.json().await.unwrap();
    let text = envelope["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result is JSON-stringified text: {envelope}"));
    serde_json::from_str(text).expect("payload is valid JSON")
}

/// AC: a headless service token is accepted on the MCP endpoint, scoped to
/// exactly its group's grants, and every call is audited to the service
/// identity.
#[tokio::test]
async fn service_token_authenticates_scopes_and_audits() {
    let gw = boot_gateway().await;

    // Accepted: 200 and group-scoped visibility — `staging` yes, `prod` no.
    let resp = call_tool(&gw, Some(CI_BOT_TOKEN), 1, "list_servers", json!({})).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload = tool_payload(resp).await;
    let rendered = payload.to_string();
    assert!(rendered.contains("\"name\":\"staging\""), "{rendered}");
    assert!(
        !rendered.contains("\"name\":\"prod\""),
        "svc-ci must not see the engineers-only server: {rendered}"
    );

    // Audit attribution: the row names the service identity, not a human.
    let row = latest_audit(
        &gw.state_db,
        "service:ci-bot",
        "list_servers",
        "service-token call",
    )
    .await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.user_email, "ci-bot@service-accounts.invalid");
    assert_eq!(row.groups, vec!["svc-ci".to_string()]);
}

/// AC: out-of-group scope is denied — audited `forbidden`, attributed to the
/// service identity. `svc-ci` has no grant on `prod`, so `describe_schema`
/// must refuse before any target connection is attempted.
#[tokio::test]
async fn service_token_outside_group_scope_is_denied_and_audited() {
    let gw = boot_gateway().await;

    let resp = call_tool(
        &gw,
        Some(CI_BOT_TOKEN),
        2,
        "describe_schema",
        json!({ "server": "prod", "database": "app" }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload = tool_payload(resp).await;
    assert_eq!(payload["code"], "forbidden", "{payload}");

    let row = latest_audit(
        &gw.state_db,
        "service:ci-bot",
        "describe_schema",
        "denied call",
    )
    .await;
    assert_eq!(row.outcome, "forbidden");
    assert_eq!(row.server.as_deref(), Some("prod"));
}

/// A recognized group with zero grants authenticates but reaches nothing —
/// the "wrong scope" floor: authentication never implies authorization.
#[tokio::test]
async fn service_token_with_empty_grants_sees_nothing() {
    let gw = boot_gateway().await;

    let resp = call_tool(&gw, Some(ANALYTICS_BOT_TOKEN), 3, "list_servers", json!({})).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload = tool_payload(resp).await;
    assert_eq!(payload["servers"], json!([]), "{payload}");

    // Audit attribution: the row names the service identity, carries the
    // empty-grant group, and uses the synthesized .invalid email — this is
    // the only proof that a zero-grant service token still flows through
    // the synchronous audit write.
    let row = latest_audit(
        &gw.state_db,
        "service:analytics-bot",
        "list_servers",
        "zero-grant call",
    )
    .await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.user_email, "analytics-bot@service-accounts.invalid");
    assert_eq!(row.groups, vec!["svc-analytics".to_string()]);
}

/// The 401 contract is unchanged: an unconfigured-but-well-formed service
/// token and no token at all are both rejected, and the anonymous case keeps
/// the exact body the live-test fence and MCP clients rely on.
#[tokio::test]
async fn unconfigured_or_missing_token_is_unauthorized() {
    let gw = boot_gateway().await;

    let resp = call_tool(&gw, Some(UNCONFIGURED_TOKEN), 4, "list_servers", json!({})).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["category"], "unauthenticated");

    let anon = call_tool(&gw, None, 5, "list_servers", json!({})).await;
    assert_eq!(anon.status(), reqwest::StatusCode::UNAUTHORIZED);
    let anon_body: Value = anon.json().await.unwrap();
    assert_eq!(anon_body["error"]["code"], "missing_bearer");
    assert_eq!(anon_body["login_url"], "/auth/login");
}

/// AC: admin reuse is not widened. A service token carries an Identity like
/// any other caller, but the admin group check rejects it — the boot-time
/// gate (service group != admin group) makes this state unreachable by
/// config, and this test proves the runtime agrees.
#[tokio::test]
async fn service_token_cannot_reach_admin_routes() {
    let gw = boot_gateway().await;

    let resp = gw
        .client
        .get(format!("{}/admin/v1/users", gw.url))
        .bearer_auth(CI_BOT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

/// Coexistence regression: with service accounts configured, the human
/// browser-SSO path still mints a working session JWT, and `engineers` scope
/// is unaffected by the headless surface.
#[tokio::test]
async fn human_session_jwt_still_works_with_service_accounts_configured() {
    let gw = boot_gateway().await;

    // Drive the mock-IdP login exactly like auth_e2e.
    let login: Value = gw
        .client
        .post(format!("{}/auth/login", gw.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = login["login_url"].as_str().unwrap().to_string();
    let authorize = gw.client.get(&login_url).send().await.unwrap();
    let callback = authorize.headers()["location"]
        .to_str()
        .unwrap()
        .to_string();
    let cb: Value = gw
        .client
        .get(&callback)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = cb["session_token"].as_str().unwrap().to_string();

    let resp = call_tool(&gw, Some(&session_token), 6, "list_servers", json!({})).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let payload = tool_payload(resp).await;
    let rendered = payload.to_string();
    assert!(rendered.contains("\"name\":\"prod\""), "{rendered}");
    assert!(
        !rendered.contains("\"name\":\"staging\""),
        "engineers must not inherit the service group's scope: {rendered}"
    );
}

/// `/auth/logout` is bearer-gated too; a service token resolves an identity
/// with no session row behind it. Logout must stay a harmless no-op (204) —
/// and must NOT kill the token: revocation is a config edit + rollout, never
/// an in-band call.
#[tokio::test]
async fn logout_is_a_noop_for_service_tokens() {
    let gw = boot_gateway().await;

    let logout = gw
        .client
        .post(format!("{}/auth/logout", gw.url))
        .bearer_auth(CI_BOT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), reqwest::StatusCode::NO_CONTENT);

    let resp = call_tool(&gw, Some(CI_BOT_TOKEN), 7, "list_servers", json!({})).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "logout must not revoke a service token"
    );

    // Audit attribution: the post-logout dispatch is still attributed to the
    // service identity — proves logout did not damage the identity behind
    // the static token (there is no session row to revoke in the first
    // place, but the audit row is the receipt).
    let row = latest_audit(
        &gw.state_db,
        "service:ci-bot",
        "list_servers",
        "post-logout call",
    )
    .await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.user_email, "ci-bot@service-accounts.invalid");
    assert_eq!(row.groups, vec!["svc-ci".to_string()]);
}

/// AC (spec 14, plan 101 slice 07): a service token's authority is exactly
/// its YAML group. A DB grant seeded for `service:<name>` — which the admin
/// API refuses to create, so only direct DB access can plant one — is
/// inert: the call is still `forbidden` and audited as such.
#[tokio::test]
async fn db_grant_seeded_for_service_identity_is_ignored() {
    let gw = boot_gateway().await;
    let repo = PgPermissionsRepo::new(gw.state_db.clone());
    let user = repo
        .upsert_user("service:ci-bot", "ci-bot@service-accounts.invalid", &[])
        .await
        .expect("seed service row");
    let db = repo
        .create_database("prod", "app", DbType::Postgres)
        .await
        .expect("seed database");
    let grant = repo
        .create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            json!({}),
        )
        .await
        .expect("seed grant");

    let resp = call_tool(
        &gw,
        Some(CI_BOT_TOKEN),
        9,
        "describe_schema",
        json!({ "server": "prod", "database": "app" }),
    )
    .await;
    let payload = tool_payload(resp).await;
    assert_eq!(payload["code"], "forbidden", "{payload}");
    let row = latest_audit(
        &gw.state_db,
        "service:ci-bot",
        "describe_schema",
        "seeded grant",
    )
    .await;
    assert_eq!(row.outcome, "forbidden");

    for (sql, id) in [
        ("DELETE FROM permissions_grants WHERE id = $1", grant.id),
        ("DELETE FROM permissions_databases WHERE id = $1", db.id),
        ("DELETE FROM permissions_users WHERE id = $1", user.id),
    ] {
        let _ = sqlx::query(sql).bind(id).execute(&gw.state_db).await;
    }
}
