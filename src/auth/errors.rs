//! Typed errors for the auth layer.
//!
//! Mapped to HTTP responses by `transport::auth_middleware` and
//! `transport::auth_routes`. Never embeds a token, code,
//! client secret, or DB credential in the `Display` impl — those would leak
//! through logs and error responses.

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Initial `reqwest::Client` build failed at boot. Surfaces only from
    /// `OidcClient::new`; we refuse to fall back to a default client because
    /// that would silently re-enable redirect following on the token-exchange
    /// path (SSRF guard).
    #[error("OIDC HTTP client init failed")]
    HttpClient,

    #[error("OIDC discovery failed")]
    Discovery,

    #[error("OIDC code exchange failed")]
    CodeExchange,

    #[error("ID token verification failed")]
    IdToken,

    /// ID token carried no usable identity: the `email` claim was absent/empty,
    /// or `email_verified` was not asserted true. Email is the audit/admin
    /// identity, so an unverified — and at many IdPs user-settable — address is
    /// refused. Kept distinct from `IdToken` so ops can tell a spoof attempt or
    /// misconfigured IdP apart from a generic token-verification failure in logs.
    #[error("ID token email is absent or unverified")]
    EmailUnverified,

    #[error("session token is invalid or expired")]
    InvalidSession,

    #[error("session has been revoked")]
    RevokedSession,

    /// The session outlived its TTL — distinct from a revocation so a client
    /// (and ops) can tell "sign in again, routinely" from "you were signed out".
    #[error("session has expired")]
    ExpiredSession,

    #[error("no session token presented")]
    MissingBearer,

    #[error("session state DB error")]
    State(#[from] sqlx::Error),

    #[error("session JWT error")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("gateway overloaded; auth store full")]
    StoreFull,
}

impl AuthError {
    /// The caller's credential is missing or no longer good: answer 401 with a
    /// `WWW-Authenticate` challenge so the client re-runs login. Every other
    /// variant is the gateway's or the IdP's failure — a 5xx with no challenge,
    /// because re-login would not fix it and would sign a working user out.
    pub fn is_credential_failure(&self) -> bool {
        matches!(
            self,
            Self::MissingBearer
                | Self::InvalidSession
                | Self::RevokedSession
                | Self::ExpiredSession
                | Self::Jwt(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_credential_variants_challenge() {
        assert!(AuthError::MissingBearer.is_credential_failure());
        assert!(AuthError::InvalidSession.is_credential_failure());
        assert!(AuthError::RevokedSession.is_credential_failure());
        assert!(AuthError::ExpiredSession.is_credential_failure());
        assert!(!AuthError::State(sqlx::Error::PoolClosed).is_credential_failure());
        assert!(!AuthError::StoreFull.is_credential_failure());
        assert!(!AuthError::Discovery.is_credential_failure());
    }
}
