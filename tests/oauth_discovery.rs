//! Integration tests for the MCP OAuth discovery surface (RFC 9728 / 8414 /
//! 7591). These exercise the unauthenticated metadata + DCR endpoints, which
//! are what a spec-compliant client (Claude Code) hits first. The full
//! authorization-code + PKCE round-trip needs a live IdP and is covered by the
//! auth e2e harness; here we lock down the discovery contract that was missing.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport::{self, AppState};
use serde_json::{Value, json};

/// Boot the gateway on an ephemeral port; return its base URL (no path).
async fn spawn_gateway() -> String {
    use db_mcp_gateway::config::ConfigFile;
    use db_mcp_gateway::exec::AdapterRegistry;
    use db_mcp_gateway::transport::ClientRegistry;
    use std::sync::Arc;

    let config = Config {
        bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        mcp_path: "/mcp".to_string(),
        ..Config::default()
    };
    let state = AppState {
        auth: None,
        config: Arc::new(ConfigFile {
            servers: Vec::new(),
            permissions: Vec::new(),
            admin: None,
            permissions_store: None,
            service_accounts: Vec::new(),
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
    let listener = tokio::net::TcpListener::bind(config.bind).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// Register a DCR client with one redirect URI; return its `client_id`.
async fn register_client(base: &str, redirect_uri: &str) -> String {
    let body: Value = client()
        .post(format!("{base}/register"))
        .json(&json!({ "redirect_uris": [redirect_uri], "client_name": "test" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["client_id"]
        .as_str()
        .expect("registration returns a client_id")
        .to_string()
}

#[tokio::test]
async fn protected_resource_metadata_names_this_gateway_as_its_auth_server() {
    let base = spawn_gateway().await;
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let resp = client().get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["resource"], format!("{base}/mcp"), "{path}");
        assert_eq!(
            body["authorization_servers"],
            json!([base]),
            "{path} must point clients back at this gateway as the AS"
        );
    }
}

#[tokio::test]
async fn authorization_server_metadata_advertises_pkce_and_endpoints() {
    let base = spawn_gateway().await;
    for path in [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    ] {
        let resp = client().get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 200, "{path}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["issuer"], base);
        assert_eq!(body["authorization_endpoint"], format!("{base}/authorize"));
        assert_eq!(body["token_endpoint"], format!("{base}/token"));
        assert_eq!(body["registration_endpoint"], format!("{base}/register"));
        assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(body["response_types_supported"], json!(["code"]));
    }
}

#[tokio::test]
async fn dynamic_client_registration_issues_a_client_id() {
    let base = spawn_gateway().await;
    let resp = client()
        .post(format!("{base}/register"))
        .json(&json!({
            "redirect_uris": ["http://127.0.0.1:33418/callback"],
            "client_name": "Claude Code",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["client_id"].as_str().is_some_and(|id| !id.is_empty()),
        "registration must return a client_id: {body}"
    );
    assert_eq!(body["token_endpoint_auth_method"], "none");
    assert_eq!(
        body["redirect_uris"],
        json!(["http://127.0.0.1:33418/callback"])
    );
}

#[tokio::test]
async fn authorize_rejects_a_request_without_pkce() {
    let base = spawn_gateway().await;
    let redirect = "http://127.0.0.1:9/cb";
    let client_id = register_client(&base, redirect).await;
    // Registered client + matching redirect, but no code_challenge → PKCE error.
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn authorize_rejects_a_request_without_state() {
    let base = spawn_gateway().await;
    let redirect = "http://127.0.0.1:9/cb";
    let client_id = register_client(&base, redirect).await;
    // Registered client + matching redirect + valid PKCE, but no `state` → the
    // gateway refuses rather than echoing an empty CSRF token back to the client.
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&client_id={client_id}\
             &redirect_uri={redirect}\
             &code_challenge=abc&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "state is required");
}

#[tokio::test]
async fn authorize_rejects_an_unregistered_client_asking_for_a_remote_redirect() {
    let base = spawn_gateway().await;
    // Well-formed PKCE request, but the client_id was never registered *and* the
    // redirect points off-box. Adopting it would let a code be delivered to a
    // host nobody vouched for — the exact hole the allowlist closes.
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&client_id=mcp-never-registered\
             &redirect_uri=https://evil.example.com/cb\
             &code_challenge=abc&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn authorize_adopts_an_unregistered_client_on_a_loopback_redirect() {
    let base = spawn_gateway().await;
    // A client whose registration lapsed (or predates the persistent store)
    // replays its cached client_id against a loopback callback. That code can
    // only reach the user's own machine, so the request proceeds instead of
    // dead-ending on `invalid_client` with nothing telling it to re-register.
    // `state` is omitted, so the request stops at the *next* gate — proof the
    // client/redirect gate let it through.
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&client_id=mcp-never-registered\
             &redirect_uri=http://127.0.0.1:9/cb\
             &code_challenge=abc&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "state is required");
}

#[tokio::test]
async fn authorize_refuses_to_adopt_an_absurd_client_id() {
    let base = spawn_gateway().await;
    // `/authorize` is unauthenticated: adoption must not become a way to write
    // arbitrary-length junk into the registry.
    let huge = "x".repeat(200);
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&client_id={huge}\
             &redirect_uri=http://127.0.0.1:9/cb\
             &code_challenge=abc&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn authorize_rejects_a_redirect_uri_the_client_did_not_register() {
    let base = spawn_gateway().await;
    // Client registered a loopback URI, then asks to be sent somewhere else.
    let client_id = register_client(&base, "http://127.0.0.1:9/cb").await;
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&client_id={client_id}\
             &redirect_uri=https://evil.example.com/cb\
             &code_challenge=abc&code_challenge_method=S256"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn registration_rejects_an_unusable_redirect_uri() {
    let base = spawn_gateway().await;
    // Non-loopback http is neither https nor loopback → rejected at /register.
    let resp = client()
        .post(format!("{base}/register"))
        .json(&json!({ "redirect_uris": ["http://evil.example.com/cb"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn token_rejects_an_unsupported_grant_type() {
    // grant_type validation runs before the session lookup, so it's observable
    // even on this auth-less harness. The authorization_code happy path + PKCE
    // verification need a wired AuthFacade and live in the auth e2e harness.
    let base = spawn_gateway().await;
    let resp = client()
        .post(format!("{base}/token"))
        .form(&[("grant_type", "client_credentials"), ("code", "irrelevant")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}
