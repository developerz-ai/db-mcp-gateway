//! End-to-end auth test: drive the full login flow against an in-process mock
//! IdP, mint a session JWT, and call a real MCP tool with the bearer.
//!
//! Requires a running state Postgres (`bin/dev up`); see CLAUDE.md.

mod common;

use common::env::state_pool;
use common::gateway::{GatewayBuilder, no_redirect_client};
use common::idp::{MockTokenFlags, MockUser, spawn_mock_idp, spawn_mock_idp_with_flags};
use serde_json::{Value, json};

/// Config the e2e booted gateway sees. The user logs in with groups
/// `[engineers, oncall]`, so `engineers` grants visibility on `prod`,
/// `oncall` on `staging`. `analytics` is visible to neither and must be
/// filtered out of `list_servers`. The literal `hunter2` is in the YAML
/// so we can assert end-to-end that it never reaches the wire.
const E2E_CONFIG_YAML: &str = r#"
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
  - name: analytics
    kind: mongo
    description: E2E analytics
    host: analytics.example.invalid
    databases:
      - { name: dw, role: ro, password: dwpw }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: schema_read }
  - group: oncall
    grants:
      - { server: staging, database: "*", action: query_read }
"#;

#[tokio::test]
async fn login_via_mock_idp_then_call_tool() {
    let pool = state_pool().await;
    // Don't TRUNCATE: tests must coexist with each other and any dev rows.

    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "e2e@example.com".to_string(),
        groups: vec!["engineers".into(), "oncall".into()],
    };
    let idp = spawn_mock_idp("test-client", "test-secret", user.clone()).await;

    let gateway_url = GatewayBuilder::new(E2E_CONFIG_YAML)
        .idp(&idp)
        .spawn(pool)
        .await
        .url;
    let client = no_redirect_client();

    // 1. Start the flow: gateway hands back the IdP authorize URL.
    let login: Value = client
        .post(format!("{gateway_url}/auth/login"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = login["login_url"]
        .as_str()
        .expect("login_url string")
        .to_string();

    // 2. Simulate the browser hitting the IdP; mock redirects to our callback.
    let authorize = client.get(&login_url).send().await.unwrap();
    assert!(authorize.status().is_redirection());
    let callback = authorize
        .headers()
        .get("location")
        .expect("authorize sets Location")
        .to_str()
        .unwrap()
        .to_string();

    // 3. Our callback: exchange + verify + mint session JWT.
    let cb: Value = client
        .get(&callback)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = cb["session_token"]
        .as_str()
        .expect("session_token string")
        .to_string();
    assert!(!session_token.is_empty());

    // 4. With the bearer, tools/call list_servers returns the caller's
    //    visible servers — and only those. User is in `engineers + oncall`,
    //    so they see `prod` + `staging`, never `analytics`. Crucially, the
    //    literal password `hunter2` from the YAML must not appear anywhere
    //    in the wire response.
    let resp: Value = client
        .post(format!("{gateway_url}/mcp"))
        .bearer_auth(&session_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "list_servers" }
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let payload = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("list_servers result is JSON-stringified text content");
    assert!(payload.contains("\"name\":\"prod\""), "{payload}");
    assert!(payload.contains("\"name\":\"staging\""), "{payload}");
    assert!(!payload.contains("\"name\":\"analytics\""), "{payload}");
    let full_response = serde_json::to_string(&resp).unwrap();
    for forbidden in ["hunter2", "stagingpw", "dwpw"] {
        assert!(
            !full_response.contains(forbidden),
            "leak: `{forbidden}` appeared in tool response: {full_response}"
        );
    }

    // 5. Without a bearer, the same call → 401 with the full unauth contract:
    //    structured error.category/code and a login_url for the agent.
    let unauth = client
        .post(format!("{gateway_url}/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "list_servers" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);
    let unauth_body: Value = unauth.json().await.unwrap();
    assert_eq!(unauth_body["error"]["category"], "unauthenticated");
    assert_eq!(unauth_body["error"]["code"], "missing_bearer");
    assert_eq!(unauth_body["login_url"], "/auth/login");

    // 6. Logout revokes; subsequent call → 401 (same contract, code differs).
    let logout = client
        .post(format!("{gateway_url}/auth/logout"))
        .bearer_auth(&session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), reqwest::StatusCode::NO_CONTENT);

    let after_logout = client
        .post(format!("{gateway_url}/mcp"))
        .bearer_auth(&session_token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "list_servers" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(after_logout.status(), reqwest::StatusCode::UNAUTHORIZED);
    let after_body: Value = after_logout.json().await.unwrap();
    assert_eq!(after_body["error"]["category"], "unauthenticated");
    assert_eq!(after_body["error"]["code"], "revoked_session");
    assert_eq!(after_body["login_url"], "/auth/login");
}

// ---------------------------------------------------------------------------
// Shared gateway setup for rejection-path tests (A5, A6).
//
// These tests need a real gateway + real state DB (SessionStore requires a
// pool) but never reach session creation — the callback fails before writing
// any rows, so no cleanup is needed.
// ---------------------------------------------------------------------------

struct GatewayHandle {
    url: String,
    client: reqwest::Client,
}

async fn spawn_gateway(pool: sqlx::PgPool, idp: &common::idp::MockIdpHandle) -> GatewayHandle {
    let gw = GatewayBuilder::new(E2E_CONFIG_YAML)
        .idp(idp)
        .spawn(pool)
        .await;
    GatewayHandle {
        url: gw.url,
        client: no_redirect_client(),
    }
}

/// Drive the login flow up to and including the `/auth/callback` response.
/// Returns the raw HTTP response so the caller can assert the status/body.
async fn drive_to_callback(gw: &GatewayHandle) -> reqwest::Response {
    let login: Value = gw
        .client
        .post(format!("{}/auth/login", gw.url))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let login_url = login["login_url"].as_str().expect("login_url").to_string();

    let authorize = gw.client.get(&login_url).send().await.unwrap();
    assert!(
        authorize.status().is_redirection(),
        "IdP must redirect to callback"
    );
    let callback = authorize
        .headers()
        .get("location")
        .expect("Location header")
        .to_str()
        .unwrap()
        .to_string();

    gw.client.get(&callback).send().await.unwrap()
}

/// A6 — ID token with `email_verified: false` must be rejected at the callback
/// with 502 Bad Gateway and error code `oidc_email_unverified`.
#[tokio::test]
async fn unverified_email_is_rejected() {
    let pool = state_pool().await;

    let user = MockUser {
        sub: format!("unverified-{}", uuid::Uuid::new_v4().simple()),
        email: "unverified@example.com".to_string(),
        groups: vec![],
    };
    let idp = spawn_mock_idp_with_flags(
        "test-client-a6",
        "test-secret-a6",
        user,
        MockTokenFlags {
            unverified_email: true,
            ..Default::default()
        },
    )
    .await;

    let gw = spawn_gateway(pool, &idp).await;
    let resp = drive_to_callback(&gw).await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "unverified email must yield 502"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "oidc_email_unverified", "{body}");
}

/// A6 — ID token with an absent/empty `email` claim must be rejected at the
/// callback with 502 Bad Gateway and error code `oidc_email_unverified`. The
/// audit/admin identity is derived from `email`, so an empty value cannot mint
/// an identity even when `email_verified` is true.
#[tokio::test]
async fn empty_email_is_rejected() {
    let pool = state_pool().await;

    let user = MockUser {
        sub: format!("empty-email-{}", uuid::Uuid::new_v4().simple()),
        email: String::new(),
        groups: vec![],
    };
    let idp = spawn_mock_idp_with_flags(
        "test-client-empty-email",
        "test-secret-empty-email",
        user,
        MockTokenFlags::default(),
    )
    .await;

    let gw = spawn_gateway(pool, &idp).await;
    let resp = drive_to_callback(&gw).await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "empty email must yield 502"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "oidc_email_unverified", "{body}");
}

/// ID token with a future-dated `nbf` (not-before) claim must be rejected at the
/// callback with 502 Bad Gateway and error code `oidc_id_token_invalid`. The
/// gateway sets `Validation::validate_nbf`, so `jsonwebtoken` refuses the
/// not-yet-valid token before any claim is trusted.
#[tokio::test]
async fn future_nbf_id_token_is_rejected() {
    let pool = state_pool().await;

    let user = MockUser {
        sub: format!("future-nbf-{}", uuid::Uuid::new_v4().simple()),
        email: "future-nbf@example.com".to_string(),
        groups: vec![],
    };
    let idp = spawn_mock_idp_with_flags(
        "test-client-nbf",
        "test-secret-nbf",
        user,
        MockTokenFlags {
            future_nbf: true,
            ..Default::default()
        },
    )
    .await;

    let gw = spawn_gateway(pool, &idp).await;
    let resp = drive_to_callback(&gw).await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "future-dated nbf must yield 502"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "oidc_id_token_invalid", "{body}");
}

/// A5 — ID token signed with HS256 must be rejected at the callback with
/// 502 Bad Gateway and error code `oidc_id_token_invalid`.
///
/// The gateway pins `Validation::new(Algorithm::RS256)`, so the HS256 header
/// causes `jsonwebtoken` to return `InvalidAlgorithm` before any signature
/// check — regardless of what key material the attacker holds.
#[tokio::test]
async fn hs256_id_token_is_rejected() {
    let pool = state_pool().await;

    let user = MockUser {
        sub: format!("hs256-attacker-{}", uuid::Uuid::new_v4().simple()),
        email: "attacker@example.com".to_string(),
        groups: vec![],
    };
    let idp = spawn_mock_idp_with_flags(
        "test-client-a5",
        "test-secret-a5",
        user,
        MockTokenFlags {
            sign_with_hs256: true,
            ..Default::default()
        },
    )
    .await;

    let gw = spawn_gateway(pool, &idp).await;
    let resp = drive_to_callback(&gw).await;

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "HS256-signed token must yield 502"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "oidc_id_token_invalid", "{body}");
}

// ---------------------------------------------------------------------------
// Slice 08 steps 1-3: a state-DB failure is the gateway's 5xx, never a 401
// that signs a working user out; logout ends every session of the subject.
// ---------------------------------------------------------------------------

const HOUR: std::time::Duration = std::time::Duration::from_secs(3600);

/// A session the gateway has never seen (its own cache stays cold), so the
/// bearer check must reach the state DB.
async fn cold_bearer(gw: &common::gateway::TestGateway, sub: &str) -> String {
    let store = db_mcp_gateway::auth::SessionStore::new(gw.state_db.clone());
    let session = store
        .create(sub, "cold@example.com", &[], HOUR, None, None)
        .await
        .expect("session row");
    db_mcp_gateway::auth::jwt::issue(&gw.auth_config.session_signing_key, session.id, sub, HOUR)
        .expect("jwt")
}

fn ping() -> Value {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
}

#[tokio::test]
async fn state_db_outage_on_bearer_check_is_5xx_without_challenge() {
    let gw = GatewayBuilder::new(E2E_CONFIG_YAML)
        .spawn(state_pool().await)
        .await;
    let sub = format!("outage-{}", uuid::Uuid::new_v4().simple());
    let bearer = cold_bearer(&gw, &sub).await;
    gw.state_db.close().await;

    let resp = no_redirect_client()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&bearer)
        .json(&ping())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_server_error(), "{}", resp.status());
    assert!(
        resp.headers().get("www-authenticate").is_none(),
        "a state-DB blip must not send the client back through login"
    );
}

#[tokio::test]
async fn logout_ends_every_session_of_the_subject() {
    let gw = GatewayBuilder::new(E2E_CONFIG_YAML)
        .spawn(state_pool().await)
        .await;
    let sub = format!("logout-all-{}", uuid::Uuid::new_v4().simple());
    let device_a = cold_bearer(&gw, &sub).await;
    let device_b = cold_bearer(&gw, &sub).await;
    let http = no_redirect_client();

    let logout = http
        .post(format!("{}/auth/logout", gw.url))
        .bearer_auth(&device_a)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), 204);

    let other_device = http
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&device_b)
        .json(&ping())
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_device.status(),
        401,
        "device B must be signed out too"
    );
}

#[tokio::test]
async fn logout_during_state_db_outage_is_5xx_not_204() {
    let gw = GatewayBuilder::new(E2E_CONFIG_YAML)
        .spawn(state_pool().await)
        .await;
    let sub = format!("logout-outage-{}", uuid::Uuid::new_v4().simple());
    // Through the gateway's own store, so its cache is warm and the bearer
    // check passes with the pool closed — only the revoke hits the DB.
    let session = gw
        .sessions
        .create(&sub, "warm@example.com", &[], HOUR, None, None)
        .await
        .expect("session row");
    let bearer = db_mcp_gateway::auth::jwt::issue(
        &gw.auth_config.session_signing_key,
        session.id,
        &sub,
        HOUR,
    )
    .expect("jwt");
    gw.state_db.close().await;

    let resp = no_redirect_client()
        .post(format!("{}/auth/logout", gw.url))
        .bearer_auth(&bearer)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_server_error(), "{}", resp.status());
    assert!(resp.headers().get("www-authenticate").is_none());
}
