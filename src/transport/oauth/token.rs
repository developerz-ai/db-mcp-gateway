use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::auth::{AuthError, pkce};

use super::super::app_state::OAuthState;
use super::helpers::{form_rejected, oauth_error, random_token};
use super::urls::MCP_SCOPE;
use crate::auth::oauth::{AuthFacade, IssuedTokens};

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
    State(state): State<OAuthState>,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Response {
    let Form(form) = match form {
        Ok(form) => form,
        Err(rejection) => return form_rejected(&rejection),
    };
    let grant = form.grant_type.as_deref();
    if grant != Some("authorization_code") && grant != Some("refresh_token") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "supported grant types: authorization_code, refresh_token",
        );
    }
    let auth = &state.auth;
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

    // redirect_uri is required on code redemption and must exactly match the
    // authorize-time value (OAuth 2.1 §4.1.3): `/authorize` always binds a
    // redirect_uri to the code, so omitting it here can't be legitimate.
    let Some(sent) = form.redirect_uri.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri is required",
        );
    };
    if sent != entry.redirect_uri {
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

    // Fresh authorization → fresh session + refresh-token chain.
    token_response(auth.issue_tokens(entry.identity, random_token()).await)
}

async fn token_refresh(auth: &AuthFacade, form: TokenForm) -> Response {
    let Some(token) = form.refresh_token.as_deref() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };
    // Rotation in one state-DB transaction: the presented token is consumed,
    // its paired session revoked, a fresh pair minted. A replayed (already
    // rotated) token finds nothing.
    match auth.rotate_tokens(token, random_token()).await {
        Ok(Some(issued)) => token_response(Ok(issued)),
        Ok(None) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token is invalid or expired",
        ),
        Err(err) => token_response(Err(err)),
    }
}

/// Render the OAuth token response (`Cache-Control: no-store`), or a 503 when
/// the state DB could not mint — never a token the store does not hold.
fn token_response(issued: Result<IssuedTokens, AuthError>) -> Response {
    let issued = match issued {
        Ok(issued) => issued,
        Err(AuthError::StoreFull) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "gateway temporarily overloaded; try again",
            );
        }
        Err(_) => {
            // No error source: `AuthError::State` can carry the DSN.
            tracing::warn!("token issuance failed (state DB)");
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "could not issue tokens; try again",
            );
        }
    };
    let body = json!({
        "access_token": issued.access_token,
        "token_type": "Bearer",
        "expires_in": issued.expires_in_secs,
        "refresh_token": issued.refresh_token,
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
