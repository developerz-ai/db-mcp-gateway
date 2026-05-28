//! Typed errors for the auth layer.
//!
//! Mapped to HTTP responses by `auth::middleware`. Never embeds a token, code,
//! client secret, or DB credential in the `Display` impl — those would leak
//! through logs and error responses.

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("OIDC discovery failed")]
    Discovery,

    #[error("OIDC code exchange failed")]
    CodeExchange,

    #[error("ID token verification failed")]
    IdToken,

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
}
