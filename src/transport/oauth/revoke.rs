use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::super::app_state::OAuthState;
use super::helpers::{form_rejected, oauth_error};

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
/// → `invalid_request` (400). A refresh token also revokes its paired access
/// session. `503` when the state DB fails: never claim a revoke that did not
/// happen.
pub async fn revoke(
    State(state): State<OAuthState>,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    let Form(form) = match form {
        Ok(form) => form,
        Err(rejection) => return form_rejected(&rejection),
    };
    let Some(token) = form.token.as_deref().filter(|t| !t.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token is required",
        );
    };
    let auth = &state.auth;

    if auth.revoke_token(token).await.is_err() {
        // No error source: `AuthError::State` wraps a sqlx::Error that can
        // carry the DSN.
        tracing::warn!("token revocation failed (state DB)");
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "token revocation is temporarily unavailable; retry",
        );
    }

    // RFC 7009 §2.2: always 200 for a well-formed request. `no-store` mirrors the
    // token endpoint so an intermediary can't cache the response.
    (
        StatusCode::OK,
        [(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")],
    )
        .into_response()
}
