//! Issue and verify the gateway's own session JWT (HS256).
//!
//! Distinct from the IdP's ID token: we re-sign so we can revoke. The JWT
//! carries only what's needed to look the session up — the authoritative
//! record (groups, revocation, expiry) lives in the state DB.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::errors::AuthError;
use super::session::SessionId;

const ISSUER: &str = "db-mcp-gateway";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub iss: String,
    pub sub: String,
    pub sid: Uuid,
    pub iat: u64,
    pub exp: u64,
}

pub fn issue(
    signing_key: &[u8],
    session_id: SessionId,
    user_sub: &str,
    ttl: Duration,
) -> Result<String, AuthError> {
    let now = unix_now();
    let claims = SessionClaims {
        iss: ISSUER.to_string(),
        sub: user_sub.to_string(),
        sid: session_id.into(),
        iat: now,
        exp: now + ttl.as_secs(),
    };
    let token = jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(signing_key),
    )?;
    Ok(token)
}

pub fn verify(signing_key: &[u8], token: &str) -> Result<SessionClaims, AuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[ISSUER]);
    validation.validate_exp = true;
    // We don't issue an aud claim; disable the default audience check.
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(signing_key),
        &validation,
    )?;
    Ok(data.claims)
}

fn unix_now() -> u64 {
    // Pre-epoch clock would yield a JWT with iat/exp in the distant past, so
    // verification fails closed. Better than panicking on the hot path.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_succeeds() {
        let key = b"test-key-please-ignore";
        let sid = SessionId::new();
        let token = issue(key, sid, "user-42", Duration::from_secs(300)).unwrap();
        let claims = verify(key, &token).unwrap();
        assert_eq!(claims.sub, "user-42");
        assert_eq!(claims.sid, Uuid::from(sid));
        assert_eq!(claims.iss, ISSUER);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sid = SessionId::new();
        let token = issue(b"key-a", sid, "user", Duration::from_secs(300)).unwrap();
        assert!(verify(b"key-b", &token).is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        // Construct directly with exp far enough in the past that jsonwebtoken's
        // default 60s leeway can't save it.
        let key = b"k";
        let sid = SessionId::new();
        let now = unix_now();
        let claims = SessionClaims {
            iss: ISSUER.into(),
            sub: "u".into(),
            sid: sid.into(),
            iat: now - 600,
            exp: now - 300,
        };
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(key),
        )
        .unwrap();
        assert!(verify(key, &token).is_err());
    }
}
