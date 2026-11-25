//! Regression tests for ID-token claim validation (OIDC Core 3.1.3.7 step 3).
//!
//! `jsonwebtoken`'s `set_issuer` / `set_audience` only constrain a claim that is
//! *present* — an absent `iss` or `aud` used to sail through, so any token
//! signed by a key in the configured IdP's JWKS verified as ours. These tests
//! drive the real `OidcClient::exchange_and_verify` path against an in-process
//! IdP that omits the claim.
//!
//! The mock is `common::idp`'s verify-only IdP (no state DB): it only needs
//! discovery, JWKS, and a token endpoint, so these run anywhere.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use db_mcp_gateway::auth::{AuthConfig, AuthError, OidcClient};
use serde_json::json;

use crate::common::idp::{TEST_KID, now_secs, sign_rs256, spawn_token_idp};

const CLIENT_ID: &str = "hardening-client";
const NONCE: &str = "hardening-nonce";

/// Which spec claim the mock IdP leaves out of the ID token.
#[derive(Clone, Copy, Debug)]
enum Omitted {
    Nothing,
    Aud,
    Iss,
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
    let idp = spawn_token_idp(move |req| Ok(sign_id_token(&req.issuer, omitted, kid))).await;
    let client = OidcClient::new(AuthConfig {
        issuer: format!("{}{issuer_suffix}", idp.issuer),
        client_id: CLIENT_ID.to_string(),
        client_secret: "hardening-secret".into(),
        audience: CLIENT_ID.to_string(),
        ..AuthConfig::default()
    })
    .expect("OidcClient http builder");
    (client, idp.jwks_hits)
}

/// RS256-sign an otherwise fully valid ID token — `kid`, `exp`, `nonce`,
/// `sub`, verified `email` — minus the omitted claim.
fn sign_id_token(issuer: &str, omitted: Omitted, kid: &str) -> String {
    let now = now_secs();
    let mut claims = json!({
        "iss": issuer,
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
    match omitted {
        Omitted::Nothing => None,
        Omitted::Aud => object.remove("aud"),
        Omitted::Iss => object.remove("iss"),
    };
    sign_rs256(&claims, kid)
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
