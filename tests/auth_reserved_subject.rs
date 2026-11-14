//! The `service:` subject prefix is reserved for YAML service identities
//! (spec 14). An IdP login whose `sub` carries it would read another
//! principal's query history and be audited as that service account, so the
//! ID-token verification refuses it.
//!
//! Self-contained mock IdP (no state DB), same shape as
//! `auth_hardening_id_token.rs`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use db_mcp_gateway::auth::{AuthConfig, AuthError, OidcClient, VerifiedIdentity};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

const TEST_KEY_PEM: &str = include_str!("data/test_idp_key.pem");
const TEST_JWK: &str = include_str!("data/test_idp_pub.jwk.json");
const TEST_KID: &str = "test-kid-1";
const CLIENT_ID: &str = "reserved-client";
const NONCE: &str = "reserved-nonce";

#[derive(Clone, Debug)]
struct MockIdp {
    issuer: String,
    sub: &'static str,
}

/// Log in at a mock IdP whose ID token names `sub`.
async fn login_as(sub: &'static str) -> Result<VerifiedIdentity, AuthError> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock IdP");
    let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks))
        .route("/token", post(token))
        .with_state(MockIdp {
            issuer: issuer.clone(),
            sub,
        });
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    OidcClient::new(AuthConfig {
        issuer,
        client_id: CLIENT_ID.to_string(),
        client_secret: "reserved-secret".into(),
        audience: CLIENT_ID.to_string(),
        ..AuthConfig::default()
    })
    .expect("OidcClient http builder")
    .exchange_and_verify("any-code", NONCE, "any-verifier")
    .await
}

async fn discovery(State(idp): State<MockIdp>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks.json", idp.issuer),
    }))
}

async fn jwks() -> Json<Value> {
    let jwk: Value = serde_json::from_str(TEST_JWK).expect("static JWK is valid JSON");
    Json(json!({ "keys": [jwk] }))
}

async fn token(State(idp): State<MockIdp>) -> Json<Value> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock past epoch")
        .as_secs();
    let claims = json!({
        "iss": idp.issuer,
        "aud": CLIENT_ID,
        "sub": idp.sub,
        "exp": now + 3600,
        "iat": now,
        "nonce": NONCE,
        "email": "mallory@example.com",
        "email_verified": true,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let id_token = jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("static test key parses"),
    )
    .expect("encode");
    Json(json!({ "token_type": "Bearer", "id_token": id_token }))
}

#[tokio::test]
async fn idp_subject_with_the_service_prefix_is_refused() {
    let result = login_as("service:bot").await;
    assert!(matches!(result, Err(AuthError::IdToken)), "got {result:?}");
}

/// Case-insensitive, so no look-alike subject can be built either.
#[tokio::test]
async fn reserved_prefix_check_ignores_case() {
    let result = login_as("Service:bot").await;
    assert!(matches!(result, Err(AuthError::IdToken)), "got {result:?}");
}

/// Only the prefix is reserved: an ordinary subject containing it still logs in.
#[tokio::test]
async fn subject_merely_containing_the_prefix_logs_in() {
    let identity = login_as("user-service:bot").await.expect("verifies");
    assert_eq!(identity.sub, "user-service:bot");
}
