//! Typed errors for the auth layer.
//!
//! Mapped to HTTP responses by `transport::auth_middleware` and
//! `transport::auth_routes`. Never embeds a token, code,
//! client secret, or DB credential in the `Display` impl — those would leak
//! through logs and error responses.

use super::oauth::StoreError;

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

    /// The state DB is down, refusing connections or shutting down: retryable,
    /// and the caller's credential is untouched. No source: a connect error
    /// can render the DSN.
    #[error("state DB unavailable")]
    StateUnavailable,

    /// The state DB answered, and refused the statement itself.
    #[error("session state DB error")]
    State(#[source] sqlx::Error),

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

impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        if is_outage(&err) {
            Self::StateUnavailable
        } else {
            Self::State(err)
        }
    }
}

impl From<StoreError> for AuthError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::StoreFull => Self::StoreFull,
            StoreError::Backend => Self::StateUnavailable,
        }
    }
}

/// Whether the state DB could not be used at all, as opposed to having refused
/// one statement.
fn is_outage(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => true,
        sqlx::Error::Database(db) => db.code().is_some_and(|code| is_outage_sqlstate(&code)),
        _ => false,
    }
}

/// Connection failure (08), login refused (28), out of connections (53),
/// shutdown or a statement cut short (57), and a standby mid-failover (25006).
fn is_outage_sqlstate(code: &str) -> bool {
    matches!(code.get(..2), Some("08" | "28" | "53" | "57")) || code == "25006"
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    use super::*;
    use crate::transport::app_state::offline_for_tests;

    async fn answer(err: AuthError) -> (StatusCode, serde_json::Value) {
        let response = err.into_response();
        let status = response.status();
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        (status, serde_json::from_slice(&body).expect("json body"))
    }

    #[tokio::test]
    async fn a_dead_state_db_a_full_store_and_a_refused_statement_answer_apart() {
        let (status, body) = answer(AuthError::StateUnavailable).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["category"], "unavailable");
        assert_eq!(body["error"]["code"], "state_db_unavailable");
        assert_eq!(
            body["error"]["message"],
            "the gateway's state database is unavailable; try again in a moment"
        );
        assert!(body.get("login_url").is_none(), "re-login cannot help");

        let (status, body) = answer(AuthError::StoreFull).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["category"], "overloaded");
        assert_eq!(body["error"]["code"], "auth_store_full");

        let (status, body) = answer(AuthError::State(sqlx::Error::RowNotFound)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"]["code"], "state_db_error");
    }

    /// A session bearer checked against a state DB that is down.
    #[tokio::test]
    async fn a_session_the_state_db_cannot_confirm_is_a_503() {
        let auth = offline_for_tests().oauth.auth;
        let unknown = uuid::Uuid::new_v4().into();
        let err = auth.sessions.lookup(unknown).await.expect_err("down");
        let (status, body) = answer(err).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "state_db_unavailable");
        assert!(!body.to_string().contains("offline.invalid"), "{body}");
    }

    #[test]
    fn an_unusable_state_db_is_unavailable_and_a_refused_statement_is_not() {
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        for outage in [
            sqlx::Error::Io(refused),
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::WorkerCrashed,
        ] {
            assert!(matches!(
                AuthError::from(outage),
                AuthError::StateUnavailable
            ));
        }
        for code in ["08006", "28P01", "53300", "57P01", "57P03", "25006"] {
            assert!(is_outage_sqlstate(code), "{code}");
        }
        for code in ["23505", "25001", "42P01", "P0001", ""] {
            assert!(!is_outage_sqlstate(code), "{code}");
        }
        assert!(matches!(
            AuthError::from(sqlx::Error::RowNotFound),
            AuthError::State(_)
        ));
    }

    #[test]
    fn a_full_store_is_not_an_unreachable_one() {
        assert!(matches!(
            AuthError::from(StoreError::StoreFull),
            AuthError::StoreFull
        ));
        assert!(matches!(
            AuthError::from(StoreError::Backend),
            AuthError::StateUnavailable
        ));
    }

    #[test]
    fn only_credential_variants_challenge() {
        assert!(AuthError::MissingBearer.is_credential_failure());
        assert!(AuthError::InvalidSession.is_credential_failure());
        assert!(AuthError::RevokedSession.is_credential_failure());
        assert!(AuthError::ExpiredSession.is_credential_failure());
        assert!(!AuthError::State(sqlx::Error::PoolClosed).is_credential_failure());
        assert!(!AuthError::StateUnavailable.is_credential_failure());
        assert!(!AuthError::StoreFull.is_credential_failure());
        assert!(!AuthError::Discovery.is_credential_failure());
    }
}
