//! HTTP routes for the login/callback/logout dance.
//!
//! Shape is intentionally simple while the MCP auth spec stabilizes — see
//! docs/initial-idea/04-auth-sso.md. /auth/login hands the agent an IdP URL
//! and a `state` token; the browser completes SSO and lands at /auth/callback
//! which returns the gateway-issued session JWT. /auth/logout revokes it.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AuthError, Identity, jwt, pkce};

use super::app_state::AppState;
use super::oauth;

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub login_url: String,
    pub state: String,
}

pub async fn login(State(state): State<AppState>) -> Result<Json<LoginResponse>, AuthError> {
    let auth = state.auth.as_ref().ok_or(AuthError::Discovery)?;
    let csrf_state = random_token();
    let nonce = random_token();
    let (verifier, challenge) = pkce::generate();
    let url = auth
        .oidc
        .authorize_url(&csrf_state, &nonce, &challenge)
        .await?;
    auth.flows.insert(csrf_state.clone(), nonce, verifier).await;
    Ok(Json(LoginResponse {
        login_url: url.to_string(),
        state: csrf_state,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct CallbackResponse {
    pub session_token: String,
    pub expires_in_seconds: u64,
}

pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    let Some(auth) = state.auth.as_ref() else {
        return AuthError::Discovery.into_response();
    };
    let Some(flow) = auth.flows.take(&params.state).await else {
        return AuthError::InvalidState.into_response();
    };

    // MCP OAuth-bridge login (`/authorize` initiated it): hand off so the
    // gateway mints an authorization code and 302s back to the client's
    // loopback redirect instead of returning the token as JSON.
    if let Some(bridge) = flow.bridge {
        return oauth::complete_bridge_login(
            &state,
            bridge,
            &params.code,
            &flow.nonce,
            &flow.idp_verifier,
        )
        .await;
    }

    // Bespoke flow: the agent POSTed `/auth/login` and polls here for the
    // session token as JSON.
    let verified = match auth
        .oidc
        .exchange_and_verify(&params.code, &flow.nonce, &flow.idp_verifier)
        .await
    {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };
    let session = match auth
        .sessions
        .create(
            &verified.sub,
            &verified.email,
            &verified.groups,
            auth.config.session_ttl,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(err) => return err.into_response(),
    };
    let token = match jwt::issue(
        &auth.config.session_signing_key,
        session.id,
        &verified.sub,
        auth.config.session_ttl,
    ) {
        Ok(t) => t,
        Err(err) => return err.into_response(),
    };
    Json(CallbackResponse {
        session_token: token,
        expires_in_seconds: auth.config.session_ttl.as_secs(),
    })
    .into_response()
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> Result<StatusCode, AuthError> {
    let auth = state.auth.as_ref().ok_or(AuthError::Discovery)?;
    auth.sessions.revoke(identity.session_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AuthError::MissingBearer
            | AuthError::InvalidSession
            | AuthError::RevokedSession
            | AuthError::Jwt(_) => StatusCode::UNAUTHORIZED,
            AuthError::Discovery
            | AuthError::CodeExchange
            | AuthError::IdToken
            | AuthError::InvalidState => StatusCode::BAD_GATEWAY,
            // `HttpClient` is a boot-time failure surface — main bails before
            // serving — so this arm is only reachable if a future caller
            // constructs an `OidcClient` lazily. Treat it as internal.
            AuthError::HttpClient | AuthError::State(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let (category, code) = auth_error_fields(&self);
        let mut body = serde_json::json!({
            "error": { "category": category, "code": code },
        });
        if status == StatusCode::UNAUTHORIZED {
            body["login_url"] = serde_json::Value::String(LOGIN_URL.to_string());
        }
        (status, Json(body)).into_response()
    }
}

/// Canonical login endpoint. Bearer middleware and `IntoResponse` both surface
/// it on 401 so agents always have one stable place to send the user.
pub(crate) const LOGIN_URL: &str = "/auth/login";

/// `(category, code)`: category groups errors for clients (e.g. retry/relogin
/// decisions); `code` is the precise reason for ops.
pub(crate) fn auth_error_fields(err: &AuthError) -> (&'static str, &'static str) {
    match err {
        AuthError::MissingBearer => ("unauthenticated", "missing_bearer"),
        AuthError::InvalidSession | AuthError::Jwt(_) => ("unauthenticated", "invalid_session"),
        AuthError::RevokedSession => ("unauthenticated", "revoked_session"),
        AuthError::Discovery => ("internal", "oidc_discovery_failed"),
        AuthError::CodeExchange => ("internal", "oidc_code_exchange_failed"),
        AuthError::IdToken => ("internal", "oidc_id_token_invalid"),
        AuthError::InvalidState => ("internal", "oidc_invalid_state"),
        AuthError::HttpClient => ("internal", "oidc_http_client_init_failed"),
        AuthError::State(_) => ("internal", "state_db_error"),
    }
}

fn random_token() -> String {
    // 128 bits of entropy from a CSPRNG (uuid v4) is plenty for CSRF/nonce.
    Uuid::new_v4().simple().to_string()
}
