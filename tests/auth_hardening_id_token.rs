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

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// `kid` the minted ID token names.
    kid: &'static str,
    jwks_hits: Arc<AtomicUsize>,
}

/// Boot a mock IdP that mints an ID token missing `omitted`, and return an
/// `OidcClient` pointed at it. The token endpoint accepts any code: these tests
/// exercise verification, not the code round-trip.
async fn client_for(omitted: Omitted) -> OidcClient {
    mock(omitted, TEST_KID, "").await.0
}

/// Like [`client_for`], with the token's `kid`, a suffix appended to the
/// configured issuer, and a counter of JWKS fetches.
async fn mock(
    omitted: Omitted,
    kid: &'static str,
    issuer_suffix: &str,
) -> (OidcClient, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock IdP");
    let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let state = MockIdp {
        issuer: issuer.clone(),
        omitted,
        kid,
        jwks_hits: Arc::clone(&jwks_hits),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks.json", get(jwks))
        .route("/token", post(token))
        .with_state(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = OidcClient::new(AuthConfig {
        issuer: format!("{issuer}{issuer_suffix}"),
        client_id: CLIENT_ID.to_string(),
        client_secret: "hardening-secret".to_string(),
        audience: CLIENT_ID.to_string(),
        ..AuthConfig::default()
    })
    .expect("OidcClient http builder");
    (client, jwks_hits)
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

async fn jwks(State(idp): State<MockIdp>) -> Json<Value> {
    idp.jwks_hits.fetch_add(1, Ordering::SeqCst);
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
    header.kid = Some(idp.kid.to_string());
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

async fn verify(client: &OidcClient) -> Result<db_mcp_gateway::auth::VerifiedIdentity, AuthError> {
    client
        .exchange_and_verify("any-code", NONCE, "any-verifier")
        .await
}

/// The JWKS is fetched once and then served from cache.
#[tokio::test]
async fn known_kid_fetches_jwks_once() {
    let (client, hits) = mock(Omitted::Nothing, TEST_KID, "").await;
    verify(&client).await.expect("first verification");
    verify(&client).await.expect("second verification");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// A token naming a `kid` the JWKS lacks triggers one refetch (the IdP may
/// have rotated keys), but repeats within the window must not hit the IdP.
#[tokio::test]
async fn unknown_kid_refetches_at_most_once_per_window() {
    let (client, hits) = mock(Omitted::Nothing, "rotated-away-kid", "").await;
    for _ in 0..3 {
        let result = verify(&client).await;
        assert!(matches!(result, Err(AuthError::IdToken)), "got {result:?}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// Concurrent first verifications share one JWKS fetch.
#[tokio::test]
async fn concurrent_cold_verifications_share_one_jwks_fetch() {
    let (client, hits) = mock(Omitted::Nothing, TEST_KID, "").await;
    let results = futures::future::join_all((0..8).map(|_| verify(&client))).await;
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// A trailing slash on the configured issuer must not reject tokens whose
/// `iss` (and discovery `issuer`) has none.
#[tokio::test]
async fn trailing_slash_on_configured_issuer_still_verifies() {
    let (client, _) = mock(Omitted::Nothing, TEST_KID, "/").await;
    verify(&client)
        .await
        .expect("issuer compared in normalized form");
}
