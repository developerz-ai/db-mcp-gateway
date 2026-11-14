//! End-to-end test for the MCP OAuth bridge: drive the full RFC 9728/8414 +
//! PKCE authorization-code flow against an in-process mock IdP, redeem the
//! code at `/token`, and call a real MCP tool with the resulting bearer.
//!
//! This is the spec-compliant path a client like Claude Code walks
//! automatically. Requires a running state Postgres (`bin/dev up`), same as
//! `auth_e2e.rs`.

use crate::common::audit::assert_audit_outcome;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, no_redirect_client, spawn_authless};
use crate::common::idp::{MockUser, spawn_mock_idp};
use db_mcp_gateway::auth::oauth::{GrantIdentity, RefreshTokens};
use db_mcp_gateway::config::Config;
use serde_json::{Value, json};

// RFC 7636 Appendix B test vector — lets the test exercise real PKCE S256
// verification without pulling sha2/base64 into the test crate.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

const CLIENT_REDIRECT: &str = "http://127.0.0.1:54599/callback";

const E2E_CONFIG_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: E2E prod
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: "*", action: schema_read }
"#;

#[tokio::test]
async fn mcp_oauth_bridge_full_flow() {
    let user = MockUser {
        sub: format!("bridge-user-{}", uuid::Uuid::new_v4().simple()),
        email: "bridge@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let sub = user.sub.clone();
    // Don't auto-follow: we assert each hop of the OAuth dance explicitly.
    let (gateway_url, client, _refresh_store) = spawn_bridge_gateway(user).await;
    let pool = state_pool().await;

    // 0. The regression itself: an unauthenticated /mcp call must carry a
    //    WWW-Authenticate header pointing at the protected-resource metadata,
    //    or the client can't begin discovery (the old behavior 404'd blindly).
    let unauth = client
        .post(format!("{gateway_url}/mcp"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "list_servers"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);
    let www = unauth
        .headers()
        .get("www-authenticate")
        .expect("401 must carry WWW-Authenticate (RFC 9728)")
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.contains("Bearer"), "{www}");
    assert!(
        www.contains("/.well-known/oauth-protected-resource"),
        "WWW-Authenticate must point at the PRM: {www}"
    );

    // 0b. Register (RFC 7591 DCR): get a client_id and pin our loopback redirect
    //     as the allowlisted URI. /authorize requires a registered client.
    let registration: Value = client
        .post(format!("{gateway_url}/register"))
        .json(&json!({ "redirect_uris": [CLIENT_REDIRECT], "client_name": "e2e" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("registration succeeds")
        .json()
        .await
        .unwrap();
    let client_id = registration["client_id"]
        .as_str()
        .expect("registration returns a client_id")
        .to_string();

    // 1. /authorize (PKCE S256) → 302 into the IdP login.
    let authorize = client
        .get(format!("{gateway_url}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "client-state-xyz"),
            ("resource", &format!("{gateway_url}/mcp")),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        authorize.status().is_redirection(),
        "authorize should 302 to the IdP, got {}",
        authorize.status()
    );
    let idp_login = location(&authorize);

    // 2. Browser → IdP → 302 back to the gateway's /auth/callback.
    let idp_redirect = client.get(&idp_login).send().await.unwrap();
    assert!(idp_redirect.status().is_redirection());
    let gateway_callback = location(&idp_redirect);
    assert!(
        gateway_callback.contains("/auth/callback"),
        "IdP should bounce to the gateway callback: {gateway_callback}"
    );

    // 3. /auth/callback recognizes the bridge flow → 302 to the CLIENT's
    //    redirect URI carrying a one-time authorization code + our state.
    let callback = client.get(&gateway_callback).send().await.unwrap();
    assert!(callback.status().is_redirection());
    let client_redirect = reqwest::Url::parse(&location(&callback)).unwrap();
    assert!(
        client_redirect.as_str().starts_with(CLIENT_REDIRECT),
        "must redirect to the client's own URI: {client_redirect}"
    );
    let mut code = None;
    let mut returned_state = None;
    for (k, v) in client_redirect.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => returned_state = Some(v.into_owned()),
            _ => {}
        }
    }
    let code = code.expect("authorization code in client redirect");
    assert_eq!(
        returned_state.as_deref(),
        Some("client-state-xyz"),
        "the client's state must be echoed back verbatim"
    );

    // 4. /token: redeem the code with the PKCE verifier → bearer access token.
    let token: Value = client
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("token exchange succeeds")
        .json()
        .await
        .unwrap();
    assert_eq!(token["token_type"], "Bearer");
    let access_token = token["access_token"]
        .as_str()
        .expect("access_token string")
        .to_string();
    assert!(!access_token.is_empty());
    let refresh_token = token["refresh_token"]
        .as_str()
        .expect("refresh_token string")
        .to_string();
    assert!(!refresh_token.is_empty());

    // 5. The access token is a working MCP bearer: list_servers sees `prod`.
    let resp: Value = client
        .post(format!("{gateway_url}/mcp"))
        .bearer_auth(&access_token)
        .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "list_servers"}}))
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
        .expect("list_servers JSON text");
    assert!(payload.contains("\"name\":\"prod\""), "{payload}");
    assert_audit_outcome(&pool, &sub, "list_servers", "success", "bridge bearer").await;

    // 6. One-time use: replaying the same code → invalid_grant.
    let replay = client
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 400);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );

    // 7. Refresh: the refresh_token mints a fresh access token (+ rotated
    //    refresh) with no browser round-trip, and the new bearer works.
    let refreshed: Value = client
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("refresh succeeds")
        .json()
        .await
        .unwrap();
    let new_access = refreshed["access_token"]
        .as_str()
        .expect("refreshed access_token");
    let new_refresh = refreshed["refresh_token"]
        .as_str()
        .expect("rotated refresh_token");
    assert_ne!(new_refresh, refresh_token, "refresh token must rotate");
    let ok = client
        .post(format!("{gateway_url}/mcp"))
        .bearer_auth(new_access)
        .json(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                      "params": {"name": "list_servers"}}))
        .send()
        .await
        .unwrap();
    assert!(ok.status().is_success(), "refreshed bearer works");
    assert_eq!(
        list_servers_rows(&pool, &sub).await,
        2,
        "refreshed call audited"
    );

    // 8. Rotation invalidates the old refresh token (OAuth 2.1 public client).
    let reused = client
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(reused.status(), 400);
    assert_eq!(
        reused.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );
    delete_audit_calls(&pool, &sub).await;
}

/// `list_servers` rows attributed to `sub`.
async fn list_servers_rows(pool: &sqlx::PgPool, sub: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_calls WHERE user_sub = $1 AND tool = 'list_servers'",
    )
    .bind(sub)
    .fetch_one(pool)
    .await
    .expect("audit count")
}

// ---------------------------------------------------------------------------
// Security tests
// ---------------------------------------------------------------------------

/// Offline gateway (no reachable IdP or state DB) — sufficient to exercise
/// `/register` and the `/authorize` parameter-validation rejection paths.
async fn spawn_authless_gateway() -> (String, reqwest::Client) {
    (
        spawn_authless(Config::default()).await,
        no_redirect_client(),
    )
}

/// Register a public client with one redirect URI; return its `client_id`.
async fn register_client(http: &reqwest::Client, gateway_url: &str, redirect_uri: &str) -> String {
    let body: Value = http
        .post(format!("{gateway_url}/register"))
        .json(&json!({ "redirect_uris": [redirect_uri] }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("registration succeeds")
        .json()
        .await
        .unwrap();
    body["client_id"]
        .as_str()
        .expect("registration returns client_id")
        .to_string()
}

/// Drive the authorize → IdP → gateway-callback → client-redirect dance;
/// return the one-time authorization code from the client's redirect URI.
async fn acquire_auth_code(
    http: &reqwest::Client,
    gateway_url: &str,
    client_id: &str,
    redirect_uri: &str,
    state_param: &str,
) -> String {
    let resp = http
        .get(format!("{gateway_url}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", state_param),
            ("resource", &format!("{gateway_url}/mcp")),
        ])
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_redirection(),
        "/authorize should 302 to IdP, got {}",
        resp.status()
    );
    let idp_redirect = http.get(location(&resp)).send().await.unwrap();
    assert!(idp_redirect.status().is_redirection());
    let callback = http.get(location(&idp_redirect)).send().await.unwrap();
    assert!(callback.status().is_redirection());
    let client_redirect = reqwest::Url::parse(&location(&callback)).unwrap();
    client_redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("authorization code in client redirect")
}

/// An `/authorize` request whose `redirect_uri` is not in the client's
/// registered allowlist must be rejected with `invalid_request`, regardless of
/// whether the URI is otherwise well-formed.
///
/// Specifically guards against:
/// - loopback URI with a different path (port-flex carve-out ≠ path-flex)
/// - external HTTPS host never registered by this client
#[tokio::test]
async fn attacker_redirect_uri_rejected() {
    let (gw, http) = spawn_authless_gateway().await;
    // CLIENT_REDIRECT = "http://127.0.0.1:54599/callback"
    let client_id = register_client(&http, &gw, CLIENT_REDIRECT).await;

    // Same host:port as CLIENT_REDIRECT but wrong path. RFC 8252 port-flex only
    // allows the *port* to vary on loopback — path must still match exactly.
    let wrong_path = http
        .get(format!("{gw}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "http://127.0.0.1:54599/evil"),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "csrf-xyz"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_path.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        wrong_path.json::<Value>().await.unwrap()["error"],
        "invalid_request",
        "loopback URI with wrong path must be rejected"
    );

    // External HTTPS host: valid format but not in this client's allowlist.
    let wrong_host = http
        .get(format!("{gw}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "https://attacker.example.com/steal"),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "csrf-xyz"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_host.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        wrong_host.json::<Value>().await.unwrap()["error"],
        "invalid_request",
        "external https URI not in allowlist must be rejected"
    );
}

/// The IdP sends the browser back with `error=access_denied` and no `code`
/// (the user declined consent). The bridge must 302 to the client's own
/// redirect with that error and its `state` — never strand the loopback
/// listener on a gateway error page.
#[tokio::test]
async fn idp_denial_redirects_back_to_the_client() {
    let user = MockUser {
        sub: format!("denied-user-{}", uuid::Uuid::new_v4().simple()),
        email: "denied@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let (gw, http, _refresh) = spawn_bridge_gateway(user).await;
    let client_id = register_client(&http, &gw, CLIENT_REDIRECT).await;

    let authorize = http
        .get(format!("{gw}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "client-csrf-1"),
        ])
        .send()
        .await
        .unwrap();
    assert!(authorize.status().is_redirection());
    // The gateway's own `state` for the IdP leg, as the IdP would echo it.
    let idp_url = reqwest::Url::parse(&location(&authorize)).unwrap();
    let idp_state = idp_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state on the IdP authorize URL");

    let callback = http
        .get(format!("{gw}/auth/callback"))
        .query(&[
            ("error", "access_denied"),
            ("error_description", "user said no"),
            ("state", idp_state.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert!(callback.status().is_redirection(), "{}", callback.status());
    let back = reqwest::Url::parse(&location(&callback)).unwrap();
    assert!(back.as_str().starts_with(CLIENT_REDIRECT), "{back}");
    let pairs: Vec<(String, String)> = back.query_pairs().into_owned().collect();
    assert!(
        pairs.contains(&("error".into(), "access_denied".into())),
        "{back}"
    );
    assert!(
        pairs.contains(&("state".into(), "client-csrf-1".into())),
        "{back}"
    );
    assert!(
        !back.as_str().contains("user+said+no"),
        "the IdP's free-text description stays server-side: {back}"
    );
}

/// `/authorize` without a `state` parameter (absent or empty) must return
/// `invalid_request`. `state` is the client's CSRF token; accepting a missing
/// one leaves the callback with no value to bind against, defeating the
/// CSRF protection that state provides.
#[tokio::test]
async fn missing_state_rejected() {
    let (gw, http) = spawn_authless_gateway().await;
    let client_id = register_client(&http, &gw, CLIENT_REDIRECT).await;

    // Completely absent `state`.
    let absent = http
        .get(format!("{gw}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            // no state
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(absent.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = absent.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request", "absent state: {body}");

    // Explicitly empty `state` — treated the same as absent.
    let empty = http
        .get(format!("{gw}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(empty.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        empty.json::<Value>().await.unwrap()["error"],
        "invalid_request",
        "empty state must also be rejected"
    );
}

/// The authorization code issued by `/auth/callback` is bound to the exact
/// `(client_id, redirect_uri, PKCE-challenge)` tuple recorded at `/authorize`.
/// `/token` must return `invalid_grant` for any mismatch — even when the
/// attacker supplies a loopback port that *would* match under the RFC 8252
/// port-flex rule at `/authorize`.
#[tokio::test]
async fn code_bound_to_client_redirect_challenge() {
    let user = MockUser {
        sub: format!("bound-user-{}", uuid::Uuid::new_v4().simple()),
        email: "bound@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let (gateway_url, http, _refresh_store) = spawn_bridge_gateway(user).await;

    let client_id = register_client(&http, &gateway_url, CLIENT_REDIRECT).await;

    // Case 1: wrong redirect_uri at /token.
    //
    // The code is bound to CLIENT_REDIRECT ("…:54599/callback"). A different
    // loopback port ("…:9999/callback") would satisfy the RFC 8252 port-flex
    // rule at /authorize, but /token uses exact string comparison — so any
    // deviation yields invalid_grant.
    let code1 = acquire_auth_code(&http, &gateway_url, &client_id, CLIENT_REDIRECT, "s1").await;
    let wrong_redirect = http
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code1.as_str()),
            ("redirect_uri", "http://127.0.0.1:9999/callback"),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_redirect.status(), 400);
    assert_eq!(
        wrong_redirect.json::<Value>().await.unwrap()["error"],
        "invalid_grant",
        "redirect_uri mismatch must yield invalid_grant"
    );

    // Case 2: wrong PKCE verifier.
    //
    // The code was issued for PKCE_CHALLENGE (S256 of PKCE_VERIFIER). Any
    // other verifier fails the SHA-256 comparison and yields invalid_grant.
    let code2 = acquire_auth_code(&http, &gateway_url, &client_id, CLIENT_REDIRECT, "s2").await;
    let wrong_verifier = http
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code2.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", "not-the-right-verifier-for-this-challenge"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_verifier.status(), 400);
    assert_eq!(
        wrong_verifier.json::<Value>().await.unwrap()["error"],
        "invalid_grant",
        "bad PKCE verifier must yield invalid_grant"
    );

    // Case 3: wrong client_id at /token.
    //
    // client_id is optional for public clients (RFC 6749 §3.2.1), but when
    // sent it must match the code's originating client. Cross-client code
    // injection must fail even when the attacker knows the verifier.
    let code3 = acquire_auth_code(&http, &gateway_url, &client_id, CLIENT_REDIRECT, "s3").await;
    let wrong_client = http
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code3.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("client_id", "mcp-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_client.status(), 400);
    assert_eq!(
        wrong_client.json::<Value>().await.unwrap()["error"],
        "invalid_grant",
        "client_id mismatch must yield invalid_grant"
    );
}

// ---------------------------------------------------------------------------
// Revocation & logout (O4): logout purges this identity's refresh chains, and
// RFC 7009 `/revoke` invalidates a presented refresh or access token.
// ---------------------------------------------------------------------------

/// Boot a full gateway (mock IdP + real state DB) wired for the OAuth bridge.
/// Returns the gateway base URL, a non-redirect-following HTTP client, and a
/// shared handle to the refresh-token store so tests can directly manipulate
/// chain state (e.g. backdate `issued_at` to simulate TTL expiry).
async fn spawn_bridge_gateway(user: MockUser) -> (String, reqwest::Client, RefreshTokens) {
    let pool = state_pool().await;
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    // `RefreshTokens` wraps an `Arc<Mutex<…>>`, so this clone shares the
    // same storage as the one placed into `AppState`.
    let refresh = RefreshTokens::default();
    let gw = GatewayBuilder::new(E2E_CONFIG_YAML)
        .idp(&idp)
        .refresh(refresh.clone())
        .spawn(pool)
        .await;
    (gw.url, no_redirect_client(), refresh)
}

/// Run register → authorize → callback → token to obtain an `(access, refresh)`
/// pair, exactly as a spec-compliant client would.
async fn obtain_token_pair(http: &reqwest::Client, gateway_url: &str) -> (String, String) {
    let client_id = register_client(http, gateway_url, CLIENT_REDIRECT).await;
    let code = acquire_auth_code(http, gateway_url, &client_id, CLIENT_REDIRECT, "tok").await;
    let token: Value = http
        .post(format!("{gateway_url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("token exchange succeeds")
        .json()
        .await
        .unwrap();
    let access = token["access_token"]
        .as_str()
        .expect("access_token")
        .to_string();
    let refresh = token["refresh_token"]
        .as_str()
        .expect("refresh_token")
        .to_string();
    (access, refresh)
}

/// O4: logging out must purge the identity's refresh-token chains, not just
/// revoke the current session row — otherwise a logged-out client could silently
/// mint a fresh session via the refresh grant.
#[tokio::test]
async fn logout_purges_refresh_tokens() {
    let user = MockUser {
        sub: format!("logout-user-{}", uuid::Uuid::new_v4().simple()),
        email: "logout@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let (gw, http, _refresh_store) = spawn_bridge_gateway(user).await;
    let (access, refresh) = obtain_token_pair(&http, &gw).await;

    let logout = http
        .post(format!("{gw}/auth/logout"))
        .bearer_auth(&access)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), reqwest::StatusCode::NO_CONTENT);

    // The refresh chain is gone: a silent renew now fails (pre-O4 it succeeded).
    let renew = http
        .post(format!("{gw}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(renew.status(), 400);
    assert_eq!(
        renew.json::<Value>().await.unwrap()["error"],
        "invalid_grant",
        "refresh token must not survive logout"
    );
}

/// RFC 7009 `/revoke`: a presented refresh token is killed (no further renewal),
/// a presented access token has its session revoked (bearer stops working), an
/// unknown token still returns 200 (no validity probe), and a missing token is
/// the lone 400.
#[tokio::test]
async fn revoke_endpoint_invalidates_refresh_and_access_tokens() {
    let user = MockUser {
        sub: format!("revoke-user-{}", uuid::Uuid::new_v4().simple()),
        email: "revoke@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let sub = user.sub.clone();
    let (gw, http, _refresh_store) = spawn_bridge_gateway(user).await;
    let pool = state_pool().await;

    // --- Refresh-token revocation ---
    let (_access1, refresh1) = obtain_token_pair(&http, &gw).await;
    let revoked = http
        .post(format!("{gw}/revoke"))
        .form(&[
            ("token", refresh1.as_str()),
            ("token_type_hint", "refresh_token"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), reqwest::StatusCode::OK);
    let renew = http
        .post(format!("{gw}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh1.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(renew.status(), 400);
    assert_eq!(
        renew.json::<Value>().await.unwrap()["error"],
        "invalid_grant"
    );

    // --- Access-token revocation (RFC 7009 §2.1: kill the access token too) ---
    let (access2, _refresh2) = obtain_token_pair(&http, &gw).await;
    let mcp_call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "list_servers"}});
    let before = http
        .post(format!("{gw}/mcp"))
        .bearer_auth(&access2)
        .json(&mcp_call)
        .send()
        .await
        .unwrap();
    assert!(before.status().is_success(), "bearer works before revoke");
    assert_audit_outcome(&pool, &sub, "list_servers", "success", "pre-revoke call").await;

    let revoked_access = http
        .post(format!("{gw}/revoke"))
        .form(&[("token", access2.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(revoked_access.status(), reqwest::StatusCode::OK);

    let after = http
        .post(format!("{gw}/mcp"))
        .bearer_auth(&access2)
        .json(&mcp_call)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "session revoked → bearer rejected"
    );
    assert_eq!(
        list_servers_rows(&pool, &sub).await,
        1,
        "the rejected bearer must not reach dispatch"
    );
    delete_audit_calls(&pool, &sub).await;

    // --- RFC 7009 §2.2: unknown token still 200; missing token → 400 ---
    let unknown = http
        .post(format!("{gw}/revoke"))
        .form(&[("token", "not-a-real-token")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown.status(),
        reqwest::StatusCode::OK,
        "unknown token must not leak validity"
    );
    let missing = http
        .post(format!("{gw}/revoke"))
        .form(&[("token_type_hint", "refresh_token")])
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 400);
    assert_eq!(
        missing.json::<Value>().await.unwrap()["error"],
        "invalid_request"
    );
}

// ---------------------------------------------------------------------------
// Token-lifecycle security tests (O3/O3b)
// ---------------------------------------------------------------------------

/// A rotated refresh token must not be accepted a second time — this is the
/// key defence against refresh-token theft / replay attacks (RFC 9449 threat
/// model). After one successful rotation the original token is consumed; any
/// subsequent presentation of that same token (by an attacker who captured it
/// in transit, or the client racing against the server) must yield
/// `invalid_grant` with no new session minted.
#[tokio::test]
async fn rotated_refresh_replay_is_invalid_grant() {
    let user = MockUser {
        sub: format!("replay-user-{}", uuid::Uuid::new_v4().simple()),
        email: "replay@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let (gw, http, _refresh_store) = spawn_bridge_gateway(user).await;
    let (_access, original_refresh) = obtain_token_pair(&http, &gw).await;

    // Legitimate rotation: `original_refresh` is consumed, a new pair is issued.
    let rotated: Value = http
        .post(format!("{gw}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", original_refresh.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("first rotation succeeds")
        .json()
        .await
        .unwrap();
    let new_refresh = rotated["refresh_token"]
        .as_str()
        .expect("rotated refresh_token");
    assert_ne!(
        new_refresh, original_refresh,
        "rotation must issue a new token"
    );

    // Attacker (or racing client) replays the now-consumed original token.
    // Must fail — the store removed it the moment it was first redeemed.
    let replay = http
        .post(format!("{gw}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", original_refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 400, "replayed token must be rejected");
    assert_eq!(
        replay.json::<Value>().await.unwrap()["error"],
        "invalid_grant",
        "replaying a rotated refresh token must yield invalid_grant"
    );
}

/// Once a refresh-token chain's absolute TTL is reached, further renewals must
/// fail with `invalid_grant`, forcing a fresh browser login that re-reads the
/// current IdP groups (O3b). Without this cap a silently-rotated chain would
/// live forever carrying the user's groups frozen at first login, so a removed
/// group would never reach the gateway.
///
/// The TTL is 24 h — too long to wait in a test — so we manipulate the
/// in-process store directly: `insert_rotated` with a stale `issued_at`
/// overwrites the live entry with one the GC considers expired. The test then
/// exercises the full HTTP path (`/token` → `RefreshTokens::take` → GC drop →
/// `invalid_grant` response) without real-time waiting.
#[tokio::test]
async fn refresh_chain_expires_past_absolute_ttl() {
    let user = MockUser {
        sub: format!("ttl-user-{}", uuid::Uuid::new_v4().simple()),
        email: "ttl@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let (gw, http, refresh_store) = spawn_bridge_gateway(user.clone()).await;
    let (_access, refresh_token) = obtain_token_pair(&http, &gw).await;

    // The absolute chain TTL is 24 h; backdate by 25 h to land clearly past it.
    let stale_birth = chrono::Utc::now() - chrono::Duration::hours(25);

    // Overwrite the live entry with a stale `issued_at`. The raw token hashes
    // to the same map key, so this replaces the existing entry in place.
    let stale_identity = GrantIdentity {
        sub: user.sub.clone(),
        email: user.email.clone(),
        groups: user.groups.clone(),
    };
    refresh_store
        .insert_rotated(&refresh_token, stale_identity, stale_birth)
        .await
        .unwrap();

    // `/token` calls `take()`, which GC-drops any entry with
    // `now - issued_at >= REFRESH_TTL`. The entry is gone → `invalid_grant`.
    let renew = http
        .post(format!("{gw}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(
        renew.status(),
        400,
        "expired-chain refresh must be rejected"
    );
    assert_eq!(
        renew.json::<Value>().await.unwrap()["error"],
        "invalid_grant",
        "refresh past the absolute chain TTL must yield invalid_grant"
    );
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("location")
        .expect("redirect sets Location")
        .to_str()
        .unwrap()
        .to_string()
}

/// Slice 08 step 4: a refresh rotates in one transaction that also revokes the
/// session the old refresh token was paired with — the pre-rotation access
/// token stops working.
#[tokio::test]
async fn refresh_revokes_the_previous_access_token() {
    let user = MockUser {
        sub: format!("rotate-access-{}", uuid::Uuid::new_v4().simple()),
        email: "rotate@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let (gw, http, _refresh_store) = spawn_bridge_gateway(user).await;
    let (old_access, refresh) = obtain_token_pair(&http, &gw).await;

    http.post(format!("{gw}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("rotation succeeds");

    let stale = http
        .post(format!("{gw}/mcp"))
        .bearer_auth(&old_access)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// RFC 7009 says 200 for an unknown token, but a revoke the state DB could not
/// perform is not "unknown": it is a 503, never a 200 that leaves the bearer
/// live.
#[tokio::test]
async fn revoke_during_state_db_outage_is_503() {
    let user = MockUser {
        sub: format!("revoke-outage-{}", uuid::Uuid::new_v4().simple()),
        email: "revoke@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    let pool = state_pool().await;
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;
    let gw = GatewayBuilder::new(E2E_CONFIG_YAML)
        .idp(&idp)
        .spawn(pool.clone())
        .await;
    let http = no_redirect_client();
    let (access, _refresh) = obtain_token_pair(&http, &gw.url).await;
    pool.close().await;

    let resp = http
        .post(format!("{}/revoke", gw.url))
        .form(&[("token", access.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "server_error");
}
