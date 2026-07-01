use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use chrono::{Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{jwt, pkce};

use super::super::app_state::{AppState, AuthFacade};
use super::super::oauth_state::GrantIdentity;
use super::helpers::{oauth_error, random_token};
use super::urls::MCP_SCOPE;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: Option<String>,
    // authorization_code grant:
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    // refresh_token grant:
    refresh_token: Option<String>,
    /// RFC 6749 §3.2.1: public clients SHOULD send `client_id`; when present,
    /// verify it matches the registered client that obtained the authorization
    /// code (prevents code-injection across clients).
    client_id: Option<String>,
}

/// `POST /token` — redeem an authorization code or a refresh token. For
/// `authorization_code`, verifies the PKCE `code_verifier` against the stored
/// S256 challenge and the `redirect_uri` match; for `refresh_token`, rotates
/// the token. Both mint a fresh gateway session and return the session JWT as
/// the bearer access token plus a new refresh token.
pub async fn token(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<TokenForm>,
) -> Response {
    // Validate the grant before touching auth state so a malformed request is a
    // clean 400 regardless of wiring.
    let grant = form.grant_type.as_deref();
    if grant != Some("authorization_code") && grant != Some("refresh_token") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "supported grant types: authorization_code, refresh_token",
        );
    }
    let Some(auth) = state.auth.as_ref() else {
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "auth not configured",
        );
    };
    if grant == Some("refresh_token") {
        token_refresh(auth, form).await
    } else {
        token_authorization_code(auth, form).await
    }
}

async fn token_authorization_code(auth: &AuthFacade, form: TokenForm) -> Response {
    let (Some(code), Some(verifier)) = (form.code.as_deref(), form.code_verifier.as_deref()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code and code_verifier are required",
        );
    };

    // One-time: take() removes the code so a replay finds nothing.
    let Some(entry) = auth.codes.take(code).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code is invalid or expired",
        );
    };

    // client_id, when sent, must match the registrant (RFC 6749 §3.2.1).
    // Public clients aren't authenticated by secret, but binding the code to
    // its originating client_id prevents cross-client code-injection.
    if let Some(sent) = form.client_id.as_deref()
        && sent != entry.client_id
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id mismatch",
        );
    }

    // redirect_uri, when sent, must match the authorize-time value (OAuth 2.1).
    if let Some(sent) = form.redirect_uri.as_deref()
        && sent != entry.redirect_uri
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }

    if !pkce::verify(verifier, &entry.code_challenge) {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }

    // Fresh authorization → fresh refresh-token chain (no carried birth time).
    issue_token_response(auth, entry.identity, None).await
}

async fn token_refresh(auth: &AuthFacade, form: TokenForm) -> Response {
    let Some(token) = form.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    // Rotation: take() consumes the presented token; `issue_token_response`
    // mints a fresh one. A replayed (already-rotated) token finds nothing.
    let Some(entry) = auth.refresh.take(token).await else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token is invalid or expired",
        );
    };
    // Carry the chain's original birth time so rotation renews the token value
    // but never extends the absolute TTL. `entry.identity` (groups included) is
    // the one frozen at the original browser login, so this same cap also bounds
    // how long a since-revoked group keeps minting sessions (O3b): the chain dies
    // REFRESH_TTL after the first mint, forcing a fresh `/authorize` that
    // re-reads groups from the IdP.
    let issued_at = entry.issued_at;
    issue_token_response(auth, entry.identity, Some(issued_at)).await
}

/// Mint a fresh session for `identity`, issue the session JWT as the access
/// token, mint+store a rotating refresh token, and render the OAuth token
/// response (with `Cache-Control: no-store`).
///
/// `chain_issued_at` is `None` for a fresh authorization (the new refresh token
/// starts its own chain) and `Some(birth)` for a rotation (the new token
/// inherits the chain's original mint time so the absolute TTL doesn't slide).
async fn issue_token_response(
    auth: &AuthFacade,
    identity: GrantIdentity,
    chain_issued_at: Option<Instant>,
) -> Response {
    // Preserve the original `/authorize` login time so `admin.session_max_age_secs`
    // counts from the first login, not from this rotation. The refresh-token chain
    // already carries the birth `Instant`; convert it to wall-clock by subtracting
    // the elapsed monotonic time from `Utc::now()`. `None` on fresh authorizations:
    // stamp `issued_at` as now (handled inside `SessionStore::create`).
    let original_issued_at = chain_issued_at.map(|birth| {
        let elapsed = Instant::now().saturating_duration_since(birth);
        Utc::now() - ChronoDuration::from_std(elapsed).unwrap_or_default()
    });

    let session = match auth
        .sessions
        .create(
            &identity.sub,
            &identity.email,
            &identity.groups,
            auth.config.session_ttl,
            None,
            original_issued_at,
        )
        .await
    {
        Ok(s) => s,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not create session",
            );
        }
    };
    let access_token = match jwt::issue(
        &auth.config.session_signing_key,
        session.id,
        &identity.sub,
        auth.config.session_ttl,
    ) {
        Ok(t) => t,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not issue token",
            );
        }
    };
    let refresh_token = random_token();
    let refresh_result = match chain_issued_at {
        Some(issued_at) => {
            auth.refresh
                .insert_rotated(&refresh_token, identity, issued_at)
                .await
        }
        None => auth.refresh.insert(&refresh_token, identity).await,
    };
    if refresh_result.is_err() {
        return oauth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_error",
            "gateway temporarily overloaded; try again",
        );
    }

    let body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": auth.config.session_ttl.as_secs(),
        "refresh_token": refresh_token,
        "scope": MCP_SCOPE,
    });
    // OAuth 2.1 §Token Response: token responses must not be cached.
    (
        StatusCode::OK,
        [(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")],
        Json(body),
    )
        .into_response()
}
