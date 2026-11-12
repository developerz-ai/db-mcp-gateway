//! Bearer-auth middleware for the MCP POST endpoint.
//!
//! Two credential kinds are accepted, tried in order:
//!
//! 1. **Service token** — a static bearer from `service_accounts:` (spec 14),
//!    matched constant-time against the boot-resolved store. Carries its own
//!    permissions group + audit identity; no session row exists.
//! 2. **Session JWT** — the gateway-issued JWT from the OIDC login flow,
//!    verified then resolved in the store (which honors revocation and expiry).
//!
//! On success, an `Identity` is attached to request extensions for downstream
//! handlers and the audit layer to read; a service token also attaches its
//! account's `ServicePolicy`.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth::{AuthError, Identity, SessionId, SessionStore};

use super::app_state::OAuthState;
use super::auth_routes::{LOGIN_URL, auth_error_fields};
use super::oauth;
use super::request_id::GatewayRequestId;
use crate::auth::oauth::AuthFacade;

pub async fn bearer_auth(
    State(state): State<OAuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth = &state.auth;
    let token = match bearer_token(&req) {
        Ok(t) => t.to_string(),
        Err(err) => return unauthorized(&state, &req, err),
    };

    // Service tokens first: an exact static match needs no DB round-trip, and
    // a non-match costs nothing (constant-time compare against a handful of
    // configured values) before the JWT path runs unchanged.
    let identity = match auth.service_tokens.load().authenticate_caller(&token) {
        Some((identity, policy)) => {
            // Read by the concurrency limiter and the upstream-header check.
            req.extensions_mut().insert(policy);
            identity
        }
        None => match resolve_identity(auth, &token).await {
            Ok(id) => id,
            Err(err) if err.is_credential_failure() => return unauthorized(&state, &req, err),
            // State-DB / gateway failure: a 5xx with no challenge — re-login
            // would not fix it, and a state-DB blip must not sign users out.
            Err(err) => {
                tracing::warn!(error = %err, request_id = %GatewayRequestId::of(&req), "bearer check failed");
                return err.into_response();
            }
        },
    };

    tracing::debug!(user_sub = %identity.user_sub, session = ?identity.session_id, "request authenticated");
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
    let claims = auth.jwt.verify(token)?;
    lookup(&auth.sessions, SessionId::from(claims.sid)).await
}

async fn lookup(sessions: &SessionStore, id: SessionId) -> Result<Identity, AuthError> {
    sessions.lookup(id).await
}

fn unauthorized(state: &OAuthState, req: &Request, err: AuthError) -> Response {
    // Only the typed reason — never embed the token or the underlying error
    // string. `login_url` is stable; agents redirect users there.
    let (category, code) = auth_error_fields(&err);
    let body = json!({
        "error": { "category": category, "code": code },
        "login_url": LOGIN_URL,
        "request_id": GatewayRequestId::of(req).to_string(),
    });
    let mut response = (StatusCode::UNAUTHORIZED, Json(body)).into_response();
    // RFC 9728 §5.1 / MCP Authorization spec: point spec-compliant clients at
    // the protected-resource metadata so they can discover the authorization
    // server and run the OAuth flow. Without this header, a client like Claude
    // Code falls back to probing `/.well-known/*` blindly and reports an
    // opaque discovery error on the 404s.
    // If base_url fails (unparseable configured redirect_url), propagate its
    // OAuth error response — a stable `server_error` body — rather than a bare
    // 500, so the client sees the gateway is broken, not their credentials.
    let base = match oauth::base_url(state) {
        Ok(base) => base,
        Err(response) => return *response,
    };
    let www = format!(
        "Bearer resource_metadata=\"{}\"",
        oauth::resource_metadata_url(&base)
    );
    if let Ok(value) = HeaderValue::from_str(&www) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}
