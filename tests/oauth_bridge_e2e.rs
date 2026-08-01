//! End-to-end test for the MCP OAuth bridge: drive the full RFC 9728/8414 +
//! PKCE authorization-code flow against an in-process mock IdP, redeem the
//! code at `/token`, and call a real MCP tool with the resulting bearer.
//!
//! This is the spec-compliant path a client like Claude Code walks
//! automatically. Requires a running state Postgres (`bin/dev up`), same as
//! `auth_e2e.rs`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{MockUser, spawn_mock_idp};
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::transport::{
    self, AppState, AuthCodes, AuthFacade, GrantIdentity, PendingFlows, RefreshTokens,
};
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

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

#[tokio::test]
async fn mcp_oauth_bridge_full_flow() {
    let user = MockUser {
        sub: format!("bridge-user-{}", uuid::Uuid::new_v4().simple()),
        email: "bridge@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
    // Don't auto-follow: we assert each hop of the OAuth dance explicitly.
    let (gateway_url, client, _refresh_store) = spawn_bridge_gateway(user).await;

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
}

// ---------------------------------------------------------------------------
// Security tests
// ---------------------------------------------------------------------------

/// Spawn a gateway with no auth and no state DB — sufficient to exercise
/// `/register` and the `/authorize` parameter-validation rejection paths.
/// Production-sized concurrency caps.
async fn spawn_authless_gateway() -> (String, reqwest::Client) {
    spawn_authless_gateway_with_caps(Config::default().max_concurrent_requests).await
}

/// Same as [`spawn_authless_gateway`], but with `max_concurrent_requests`
/// overridden — lets a test drive the global concurrency cap into
/// contention without needing hundreds of simultaneous connections.
async fn spawn_authless_gateway_with_caps(
    max_concurrent_requests: usize,
) -> (String, reqwest::Client) {
    use db_mcp_gateway::config::ConfigFile;
    use db_mcp_gateway::exec::AdapterRegistry;
    use db_mcp_gateway::transport::ClientRegistry;
    use std::sync::Arc;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind authless gateway");
    let addr = listener.local_addr().unwrap();
    let gateway_url = format!("http://{addr}");
    let config = Config {
        bind: addr,
        max_concurrent_requests,
        ..Config::default()
    };
    let state = AppState {
        auth: None,
        config: Arc::new(ConfigFile {
            servers: Vec::new(),
            permissions: Vec::new(),
            admin: None,
            permissions_store: None,
        }),
        adapter_registry: AdapterRegistry::new(),
        state_db: None,
        shutdown: Default::default(),
        metrics: None,
        permissions_cache: None,
        permissions_repo: None,
        mcp_path: Arc::from("/mcp"),
        client_registry: ClientRegistry::default(),
    };
    let app = transport::router(&config, state).expect("router builds");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    (gateway_url, client)
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

/// Regression for the #136 audit finding "/authorize flood wedges all
/// logins ... the open routes skip the concurrency limiter". `/authorize`
/// must be bounded by the same global `ConcurrencyLimiter` gated traffic
/// goes through — pre-fix, this router mounted it in the `open` group,
/// which never got `limit::enforce` layered on at all, so no volume of
/// concurrent `/authorize` traffic could ever be shed.
///
/// `max_concurrent_requests: 0` gives the global semaphore zero permits, so
/// `try_acquire_owned()` fails unconditionally — deterministic, no timing
/// race needed (an earlier version of this test tried firing a burst of
/// concurrent requests against a cap of 1 and asserting at least one 503;
/// that was flaky because `/authorize`'s fast-reject validation path
/// completes faster than genuine request overlap can be engineered from a
/// test client). A single request must come back 503 if and only if
/// `/authorize` is actually routed through `limit::enforce`.
#[tokio::test]
async fn authorize_route_is_concurrency_limited() {
    let (gw, http) = spawn_authless_gateway_with_caps(0).await;

    let resp = http
        .get(format!("{gw}/authorize"))
        .send()
        .await
        .expect("request sent");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "expected 503 with a zero-permit global cap — /authorize is not routed through limit::enforce"
    );
    let body: Value = resp.json().await.expect("503 body is JSON");
    assert_eq!(body["error"]["code"], "service_overloaded");
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
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)");
    let idp = spawn_mock_idp("test-client", "test-secret", user).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway_url = format!("http://{addr}");

    let auth_config = AuthConfig {
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        client_secret: idp.client_secret.clone(),
        audience: idp.client_id.clone(),
        redirect_url: format!("{gateway_url}/auth/callback"),
        ..AuthConfig::default()
    };
    let sessions = SessionStore::new(pool.clone());
    let oidc = OidcClient::new(auth_config.clone()).expect("OidcClient http builder");
    let config = Config {
        bind: addr,
        ..Config::default()
    };
    let config_file = ConfigFile::from_yaml_str(E2E_CONFIG_YAML).expect("e2e yaml is well-formed");
    // Create the refresh-token store separately so we can hand a clone back to
    // the test. `RefreshTokens` wraps an `Arc<Mutex<…>>`, so this clone shares
    // the same storage as the one placed into `AppState`.
    let refresh = db_mcp_gateway::transport::RefreshTokens::default();
    let app = transport::router(
        &config,
        AppState {
            auth: Some(AuthFacade {
                config: Arc::new(auth_config),
                sessions,
                oidc,
                flows: PendingFlows::default(),
                codes: AuthCodes::default(),
                refresh: refresh.clone(),
            }),
            config: Arc::new(config_file),
            adapter_registry: AdapterRegistry::new(),
            state_db: Some(pool),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
            mcp_path: std::sync::Arc::from("/mcp"),
            client_registry: db_mcp_gateway::transport::ClientRegistry::default(),
        },
    )
    .expect("router builds");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    (gateway_url, client, refresh)
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
    let (gw, http, _refresh_store) = spawn_bridge_gateway(user).await;

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
