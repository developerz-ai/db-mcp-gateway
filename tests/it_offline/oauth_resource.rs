//! RFC 8707 resource indicators at `/authorize` and `/token`: the gateway
//! issues tokens for exactly one resource — the MCP endpoint its
//! protected-resource metadata advertises — and refuses any other with
//! `invalid_target` before anything is parked or consumed.

use std::time::Duration;

use crate::common::gateway::spawn_authless;
use db_mcp_gateway::config::Config;
use serde_json::{Value, json};

// RFC 7636 Appendix B test vector.
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "http://127.0.0.1:9/cb";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client")
}

async fn gateway_and_client() -> (String, String) {
    let base = spawn_authless(Config::default()).await;
    let body: Value = client()
        .post(format!("{base}/register"))
        .json(&json!({ "redirect_uris": [REDIRECT] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = body["client_id"].as_str().expect("client_id").to_owned();
    (base, client_id)
}

async fn advertised_resource(base: &str) -> String {
    let prm: Value = client()
        .get(format!("{base}/.well-known/oauth-protected-resource"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    prm["resource"].as_str().expect("resource").to_owned()
}

async fn authorize(base: &str, client_id: &str, resource: &str) -> (u16, Value) {
    let response = client()
        .get(format!("{base}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", PKCE_CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "s"),
            ("resource", resource),
        ])
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn authorize_refuses_a_resource_that_is_not_this_gateway() {
    let (base, client_id) = gateway_and_client().await;
    for foreign in [
        "https://other.example.com/mcp".to_owned(),
        format!("{base}/admin"),
        format!("{base}/mcp#x"),
    ] {
        let (status, body) = authorize(&base, &client_id, &foreign).await;
        assert_eq!(status, 400, "{foreign}: {body}");
        assert_eq!(body["error"], "invalid_target", "{foreign}: {body}");
    }
}

#[tokio::test]
async fn authorize_refuses_the_advertised_resource_with_extra_components() {
    let (base, client_id) = gateway_and_client().await;
    let ours = advertised_resource(&base).await;
    let with_userinfo = ours.replacen("://", "://agent@", 1);
    for altered in [
        format!("{ours}?tenant=other"),
        format!("{ours}?"),
        format!("{ours}#"),
        format!("{ours}//"),
        with_userinfo,
    ] {
        let (status, body) = authorize(&base, &client_id, &altered).await;
        assert_eq!(status, 400, "{altered}: {body}");
        assert_eq!(body["error"], "invalid_target", "{altered}: {body}");
    }
}

#[tokio::test]
async fn authorize_accepts_the_advertised_resource() {
    let (base, client_id) = gateway_and_client().await;
    let ours = advertised_resource(&base).await;
    // No IdP is reachable here, so the request fails later; what matters is
    // that the resource check let it through.
    let (status, body) = authorize(&base, &client_id, &ours).await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["error"], "server_error", "{body}");
}

#[tokio::test]
async fn token_refuses_a_foreign_resource_before_the_grant() {
    let (base, _) = gateway_and_client().await;
    let response = client()
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", "unknown"),
            ("resource", "https://other.example.com/mcp"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_target", "{body}");
}
