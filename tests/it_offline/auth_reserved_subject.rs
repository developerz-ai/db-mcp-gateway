//! The `service:` subject prefix is reserved for YAML service identities
//! (spec 14). An IdP login whose `sub` carries it would read another
//! principal's query history and be audited as that service account, so the
//! ID-token verification refuses it.
//!
//! Verify-only mock IdP from `common::idp`, no state DB.

use db_mcp_gateway::auth::{AuthConfig, AuthError, OidcClient, VerifiedIdentity};
use serde_json::json;

use crate::common::idp::{TEST_KID, now_secs, sign_rs256, spawn_token_idp};

const CLIENT_ID: &str = "reserved-client";
const NONCE: &str = "reserved-nonce";

/// Log in at a mock IdP whose ID token names `sub`.
async fn login_as(sub: &'static str) -> Result<VerifiedIdentity, AuthError> {
    let idp = spawn_token_idp(move |req| {
        let now = now_secs();
        let claims = json!({
            "iss": req.issuer,
            "aud": CLIENT_ID,
            "sub": sub,
            "exp": now + 3600,
            "iat": now,
            "nonce": NONCE,
            "email": "mallory@example.com",
            "email_verified": true,
        });
        Ok(sign_rs256(&claims, TEST_KID))
    })
    .await;
    OidcClient::new(AuthConfig {
        issuer: idp.issuer,
        client_id: CLIENT_ID.to_string(),
        client_secret: "reserved-secret".into(),
        audience: CLIENT_ID.to_string(),
        ..AuthConfig::default()
    })
    .expect("OidcClient http builder")
    .exchange_and_verify("any-code", NONCE, "any-verifier")
    .await
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
