use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::auth::{SessionId, jwt};

use super::super::app_state::AppState;
use super::helpers::oauth_error;

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    token: Option<String>,
    /// RFC 7009 §2.1 advisory hint (`access_token` | `refresh_token`). We probe
    /// both stores regardless of the hint, so it's accepted for compliance but
    /// not acted on.
    #[allow(dead_code)]
    token_type_hint: Option<String>,
}

/// `POST /revoke` — RFC 7009 OAuth 2.0 Token Revocation. A client presents a
/// `token` it wants invalidated (its own refresh token on sign-out, or a session
/// access token). We probe both stores: an opaque refresh token is dropped from
/// the rotation store — which ends the chain, since rotation keeps exactly one
/// live token per chain — and a session JWT has its backing session row revoked
/// so the bearer stops working immediately (RFC 7009 §2.1: kill the access token
/// too, not just the refresh token).
///
/// Per RFC 7009 §2.2 the response is `200` for any well-formed request — an
/// unknown, expired, forged, or already-revoked token included — so a caller
/// can't probe token validity here. A missing `token` is the lone malformed case
/// → `invalid_request` (400).
pub async fn revoke(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<RevokeForm>,
) -> Response {
    let Some(token) = form.token.as_deref().filter(|t| !t.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token is required",
        );
    };
    let Some(auth) = state.auth.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "auth not configured",
        );
    };

    // Refresh token: removing the presented token ends the chain (only the
    // latest token in a rotated chain is ever live).
    let refresh_revoked = auth.refresh.take(token).await.is_some();

    // Access token: a verifiable session JWT → revoke its session row. A forged
    // or expired JWT fails verification and is silently ignored.
    let session_revoked = match jwt::verify(&auth.config.session_signing_key, token) {
        Ok(claims) => auth
            .sessions
            .revoke(SessionId::from(claims.sid))
            .await
            .is_ok(),
        Err(_) => false,
    };

    // Outcome flags only — never the token itself (it would leak a live secret).
    tracing::debug!(refresh_revoked, session_revoked, "token revocation");

    // RFC 7009 §2.2: always 200 for a well-formed request. `no-store` mirrors the
    // token endpoint so an intermediary can't cache the response.
    (
        StatusCode::OK,
        [(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")],
    )
        .into_response()
}
