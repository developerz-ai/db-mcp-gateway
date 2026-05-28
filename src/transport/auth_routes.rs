//! HTTP routes for the login/callback/logout dance.
//!
//! Shape is intentionally simple while the MCP auth spec stabilizes — see
//! docs/initial-idea/04-auth-sso.md. /auth/login hands the agent an IdP URL
//! and a `state` token; the browser completes SSO and lands at /auth/callback
//! which returns the gateway-issued session JWT. /auth/logout revokes it.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AuthError, Identity, jwt};

use super::app_state::AppState;

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub login_url: String,
    pub state: String,
}

pub async fn login(State(state): State<AppState>) -> Result<Json<LoginResponse>, AuthError> {
    let auth = state.auth.as_ref().ok_or(AuthError::Discovery)?;
    let csrf_state = random_token();
    let nonce = random_token();
    let url = auth.oidc.authorize_url(&csrf_state, &nonce).await?;
    auth.flows.insert(csrf_state.clone(), nonce).await;
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
) -> Result<Json<CallbackResponse>, AuthError> {
    let auth = state.auth.as_ref().ok_or(AuthError::Discovery)?;
    let nonce = auth
        .flows
        .take(&params.state)
        .await
        .ok_or(AuthError::IdToken)?;

    let verified = auth.oidc.exchange_and_verify(&params.code, &nonce).await?;
    let session = auth
        .sessions
        .create(
            &verified.sub,
            &verified.email,
            &verified.groups,
            auth.config.session_ttl,
            None,
        )
        .await?;
    let token = jwt::issue(
        &auth.config.session_signing_key,
        session.id,
        &verified.sub,
        auth.config.session_ttl,
    )?;
    Ok(Json(CallbackResponse {
        session_token: token,
        expires_in_seconds: auth.config.session_ttl.as_secs(),
    }))
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
            AuthError::Discovery | AuthError::CodeExchange | AuthError::IdToken => {
                StatusCode::BAD_GATEWAY
            }
            AuthError::State(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = serde_json::json!({ "error": auth_error_code(&self) });
        (status, Json(body)).into_response()
    }
}

fn auth_error_code(err: &AuthError) -> &'static str {
    match err {
        AuthError::MissingBearer => "missing_bearer",
        AuthError::InvalidSession | AuthError::Jwt(_) => "invalid_session",
        AuthError::RevokedSession => "revoked_session",
        AuthError::Discovery => "oidc_discovery_failed",
        AuthError::CodeExchange => "oidc_code_exchange_failed",
        AuthError::IdToken => "oidc_id_token_invalid",
        AuthError::State(_) => "state_db_error",
    }
}

fn random_token() -> String {
    // 128 bits of entropy from a CSPRNG (uuid v4) is plenty for CSRF/nonce.
    Uuid::new_v4().simple().to_string()
}
