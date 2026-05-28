//! Bearer-auth middleware for the MCP POST endpoint.
//!
//! Extracts `Authorization: Bearer <jwt>`, verifies the gateway-issued
//! session JWT, then resolves the session in the store (which honors
//! revocation and expiry). On success, an `Identity` is attached to request
//! extensions for downstream handlers and the audit layer to read.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::{AuthError, Identity, SessionId, SessionStore, jwt};

use super::app_state::{AppState, AuthFacade};

pub async fn bearer_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        // Test bootstrap: no auth wired. Production main never builds AppState
        // this way.
        return next.run(req).await;
    };

    let token = match bearer_token(&req) {
        Ok(t) => t.to_string(),
        Err(err) => return unauthorized(err),
    };

    let identity = match resolve_identity(auth, &token).await {
        Ok(id) => id,
        Err(err) => return unauthorized(err),
    };

    tracing::debug!(user = %identity.user_sub, session = ?identity.session_id, "request authenticated");
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn bearer_token(req: &Request) -> Result<&str, AuthError> {
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingBearer)?
        .to_str()
        .map_err(|_| AuthError::MissingBearer)?;
    header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or(AuthError::MissingBearer)
}

async fn resolve_identity(auth: &AuthFacade, token: &str) -> Result<Identity, AuthError> {
    let claims = jwt::verify(&auth.config.session_signing_key, token)?;
    lookup(&auth.sessions, SessionId::from(claims.sid)).await
}

async fn lookup(sessions: &SessionStore, id: SessionId) -> Result<Identity, AuthError> {
    sessions.lookup(id).await
}

fn unauthorized(err: AuthError) -> Response {
    // Only the typed reason — never embed the token or the underlying error
    // string. login_url is stable; agents redirect users there.
    let body = json!({
        "error": match err {
            AuthError::MissingBearer => "missing_bearer",
            AuthError::InvalidSession | AuthError::Jwt(_) => "invalid_session",
            AuthError::RevokedSession => "revoked_session",
            _ => "auth_error",
        },
        "login_url": "/auth/login",
    });
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}
