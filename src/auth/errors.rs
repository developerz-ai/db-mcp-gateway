//! Typed errors for the auth layer.
//!
//! Mapped to HTTP responses by `auth::middleware`. Never embeds a token, code,
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

    /// CSRF `state` from the callback was unknown/expired/replayed. Kept
    /// distinct from `IdToken` so ops can tell the two apart in logs, even
    /// though both surface as the same HTTP code to the client.
    #[error("OIDC callback state is invalid or expired")]
    InvalidState,

    #[error("session token is invalid or expired")]
    InvalidSession,

    #[error("session has been revoked")]
    RevokedSession,

    #[error("no session token presented")]
    MissingBearer,

    #[error("session state DB error")]
    State(#[from] sqlx::Error),

    #[error("session JWT error")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("gateway overloaded; auth store full")]
    StoreFull,
}
