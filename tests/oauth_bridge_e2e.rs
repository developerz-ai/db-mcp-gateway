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
use db_mcp_gateway::transport::{self, AppState, AuthCodes, AuthFacade, PendingFlows};
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
    let pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)");

    let user = MockUser {
        sub: format!("bridge-user-{}", uuid::Uuid::new_v4().simple()),
        email: "bridge@example.com".to_string(),
        groups: vec!["engineers".into()],
    };
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
    let app = transport::router(
        &config,
        AppState {
            auth: Some(AuthFacade {
                config: Arc::new(auth_config),
                sessions,
                oidc,
                flows: PendingFlows::default(),
                codes: AuthCodes::default(),
            }),
            config: Arc::new(config_file),
            adapter_registry: AdapterRegistry::new(),
            state_db: Some(pool),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
            mcp_path: std::sync::Arc::from("/mcp"),
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

    // Don't auto-follow: we assert each hop of the OAuth dance explicitly.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

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

    // 1. /authorize (PKCE S256) → 302 into the IdP login.
    let authorize = client
        .get(format!("{gateway_url}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "mcp-test"),
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
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("location")
        .expect("redirect sets Location")
        .to_str()
        .unwrap()
        .to_string()
}
