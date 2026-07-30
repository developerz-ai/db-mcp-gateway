//! Regression tests for ID-token claim validation (OIDC Core 3.1.3.7 step 3).
//!
//! `jsonwebtoken`'s `set_issuer` / `set_audience` only constrain a claim that is
//! *present* — an absent `iss` or `aud` used to sail through, so any token
//! signed by a key in the configured IdP's JWKS verified as ours. These tests
//! drive the real `OidcClient::exchange_and_verify` path against an in-process
//! IdP that omits the claim.
//!
//! Deliberately self-contained (no `tests/common`, no state DB): the mock only
//! needs discovery, JWKS, and a token endpoint, so these run anywhere.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use db_mcp_gateway::auth::{AuthConfig, AuthError, OidcClient};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

/// Same committed test keypair the e2e mock IdP uses. Not security-sensitive:
/// the private key is plainly in the repo and never touches a prod path.
const TEST_KEY_PEM: &str = include_str!("data/test_idp_key.pem");
const TEST_JWK: &str = include_str!("data/test_idp_pub.jwk.json");
const TEST_KID: &str = "test-kid-1";
const CLIENT_ID: &str = "hardening-client";
const NONCE: &str = "hardening-nonce";

/// Which spec claim the mock IdP leaves out of the ID token.
#[derive(Clone, Copy, Debug)]
enum Omitted {
    Nothing,
    Aud,
    Iss,
}

#[derive(Clone, Debug)]
struct MockIdp {
    issuer: String,
    omitted: Omitted,
}

/// Boot a mock IdP that mints an ID token missing `omitted`, and return an
/// `OidcClient` pointed at it. The token endpoint accepts any code: these tests
/// exercise verification, not the code round-trip.
async fn client_for(omitted: Omitted) -> OidcClient {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock IdP");
    let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
    let state = MockIdp {
        issuer: issuer.clone(),
        omitted,
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks))
        .route("/token", post(token))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    OidcClient::new(AuthConfig {
        issuer,
        client_id: CLIENT_ID.to_string(),
        client_secret: "hardening-secret".to_string(),
        audience: CLIENT_ID.to_string(),
        ..AuthConfig::default()
    })
    .expect("OidcClient http builder")
}

async fn discovery(State(idp): State<MockIdp>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks.json", idp.issuer),
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn jwks(State(_): State<MockIdp>) -> Json<Value> {
    let jwk: Value = serde_json::from_str(TEST_JWK).expect("static JWK is valid JSON");
    Json(json!({ "keys": [jwk] }))
}

async fn token(State(idp): State<MockIdp>) -> Json<Value> {
    Json(json!({
        "access_token": "hardening-access",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": sign_id_token(&idp),
    }))
}

/// RS256-sign an otherwise fully valid ID token — correct `kid`, `exp`,
/// `nonce`, `sub`, verified `email` — minus the omitted claim.
fn sign_id_token(idp: &MockIdp) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock past UNIX epoch")
        .as_secs();
    let mut claims = json!({
        "iss": idp.issuer,
        "aud": CLIENT_ID,
        "sub": "hardening-subject",
        "exp": now + 3600,
        "iat": now,
        "nonce": NONCE,
        "email": "hardening@example.com",
        "email_verified": true,
        "groups": ["engineers"],
    });
    let object = claims.as_object_mut().expect("claims are a JSON object");
    match idp.omitted {
        Omitted::Nothing => None,
        Omitted::Aud => object.remove("aud"),
        Omitted::Iss => object.remove("iss"),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).expect("static test key parses"),
    )
    .expect("ID token encoding never fails for our static inputs")
}

/// Baseline: the happy path still verifies once the claims are required, so the
/// tightened `Validation` can't be passing the rejection tests vacuously.
#[tokio::test]
async fn complete_id_token_is_accepted() {
    let identity = client_for(Omitted::Nothing)
        .await
        .exchange_and_verify("any-code", NONCE, "any-verifier")
        .await
        .expect("a complete, correctly signed ID token verifies");
    assert_eq!(identity.sub, "hardening-subject");
    assert_eq!(identity.email, "hardening@example.com");
    assert_eq!(identity.groups, vec!["engineers".to_string()]);
}

/// An ID token with no `aud` must be rejected: without it, any token the IdP
/// minted for a *different* client would be accepted as ours.
#[tokio::test]
async fn id_token_without_aud_is_rejected() {
    let result = client_for(Omitted::Aud)
        .await
        .exchange_and_verify("any-code", NONCE, "any-verifier")
        .await;
    assert!(
        matches!(result, Err(AuthError::IdToken)),
        "aud-less ID token must not verify, got {result:?}"
    );
}

/// An ID token with no `iss` must be rejected for the same reason: the issuer
/// binding is what ties the signature to the configured IdP.
#[tokio::test]
async fn id_token_without_iss_is_rejected() {
    let result = client_for(Omitted::Iss)
        .await
        .exchange_and_verify("any-code", NONCE, "any-verifier")
        .await;
    assert!(
        matches!(result, Err(AuthError::IdToken)),
        "iss-less ID token must not verify, got {result:?}"
    );
}
