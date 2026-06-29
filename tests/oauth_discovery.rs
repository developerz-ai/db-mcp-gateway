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
    let config = Config {
        bind: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        mcp_path: "/mcp".to_string(),
        ..Config::default()
    };
    let app = transport::router(&config, AppState::for_tests()).expect("router builds");
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
    // response_type=code but no code_challenge → invalid_request.
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&redirect_uri=http://127.0.0.1:9/cb"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn authorize_rejects_an_untrusted_redirect_uri() {
    let base = spawn_gateway().await;
    let resp = client()
        .get(format!(
            "{base}/authorize?response_type=code&redirect_uri=http://evil.example.com/cb\
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
