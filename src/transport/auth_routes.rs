//! HTTP routes for the login/callback/logout dance.
//!
//! Shape is intentionally simple while the MCP auth spec stabilizes — see
//! website/docs/initial-idea/04-auth-sso.md. /auth/login hands the agent an IdP URL
//! and a `state` token; the browser completes SSO and lands at /auth/callback
//! which returns the gateway-issued session JWT. /auth/logout revokes it.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, PRAGMA};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::auth::{AuthError, Identity};

use super::app_state::OAuthState;
use super::oauth::{self, PageContext, random_token};
use super::request_id::GatewayRequestId;

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub login_url: String,
    pub state: String,
}

/// `no-store`: the body carries the CSRF `state` of a login in progress.
pub async fn login(State(state): State<OAuthState>) -> Result<Response, AuthError> {
    let auth = &state.auth;
    let csrf_state = random_token();
    let secrets = auth.flows.login_secrets(&csrf_state);
    let url = auth
        .oidc
        .authorize_url(&csrf_state, &secrets.nonce, &secrets.idp_challenge())
        .await?;
    // The store logged the cause; full or unreachable, a retryable 503.
    auth.flows
        .insert(&csrf_state)
        .await
        .map_err(|_| AuthError::StoreFull)?;
    Ok(no_store(Json(LoginResponse {
        login_url: url.to_string(),
        state: csrf_state,
    })))
}

/// The IdP's redirect back: `code` on success, `error` (RFC 6749 §4.1.2.1)
/// when the user declined or the IdP failed; `state` either way.
#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// `code` and `state` are single-use bearer values; the description is the
/// IdP's free text about a user.
impl std::fmt::Debug for CallbackParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackParams")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub struct CallbackResponse {
    pub session_token: String,
    pub expires_in_seconds: u64,
}

impl std::fmt::Debug for CallbackResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallbackResponse")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .finish_non_exhaustive()
    }
}

pub async fn callback(
    State(state): State<OAuthState>,
    Extension(request_id): Extension<GatewayRequestId>,
    params: Result<Query<CallbackParams>, QueryRejection>,
) -> Response {
    let Query(params) = match params {
        Ok(params) => params,
        Err(rejection) => return oauth::query_rejected(&rejection),
    };
    let auth = &state.auth;
    let page = PageContext::new(auth, request_id);
    // No live flow for this `state`: it expired (login took longer than
    // FLOW_TTL), was already consumed (double submit / reload), or the pod
    // restarted mid-login. Recoverable on OUR side — never a 502, which reads
    // as an outage and hides the fix.
    let flow = match params.state.as_deref() {
        Some(flow_state) => match auth.flows.take(flow_state).await {
            Ok(flow) => flow,
            Err(_) => return oauth::login_unavailable(&page),
        },
        None => None,
    };
    let Some(flow) = flow else {
        return oauth::login_expired(&page);
    };

    let code = match (params.code, params.error.as_deref()) {
        (Some(code), None) => code,
        (_, idp_error) => {
            let error = client_facing_idp_error(idp_error);
            // The IdP's own description stays server-side: it is free text
            // from a third party and may name the user.
            tracing::warn!(
                error,
                has_description = params.error_description.is_some(),
                "IdP returned no authorization code at /auth/callback"
            );
            return match flow.bridge {
                Some(bridge) => oauth::redirect_with_error(&bridge, error),
                None => oauth::login_not_completed(&page),
            };
        }
    };

    // MCP OAuth-bridge login (`/authorize` initiated it): hand off so the
    // gateway mints an authorization code and 302s back to the client's
    // loopback redirect instead of returning the token as JSON.
    if let Some(bridge) = flow.bridge {
        return oauth::complete_bridge_login(
            auth,
            bridge,
            &code,
            &flow.nonce,
            &flow.idp_verifier,
            &page,
        )
        .await;
    }

    // Bespoke flow: the agent POSTed `/auth/login` and polls here for the
    // session token as JSON.
    let verified = match auth
        .oidc
        .exchange_and_verify(&code, &flow.nonce, &flow.idp_verifier)
        .await
    {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };
    if verified.groups.is_empty() {
        tracing::warn!(%request_id, "login carries no groups; group grants will not apply to it");
    }
    let session_ttl = auth.login_session_ttl();
    let session = match auth
        .sessions
        .create(
            &verified.sub,
            &verified.email,
            &verified.groups,
            session_ttl,
            None, // fresh login: stamp issued_at now
        )
        .await
    {
        Ok(s) => s,
        Err(err) => return err.into_response(),
    };
    let token = match auth.jwt.issue(session.id, &verified.sub, session_ttl) {
        Ok(t) => t,
        Err(err) => return err.into_response(),
    };
    no_store(Json(CallbackResponse {
        session_token: token,
        expires_in_seconds: session_ttl.as_secs(),
    }))
}

/// A bearer or a login secret in the body: no cache may keep it (RFC 6749
/// §5.1, as `/token` answers).
fn no_store(body: impl IntoResponse) -> Response {
    ([(CACHE_CONTROL, "no-store"), (PRAGMA, "no-cache")], body).into_response()
}

pub async fn logout(
    State(state): State<OAuthState>,
    Extension(identity): Extension<Identity>,
) -> Result<StatusCode, AuthError> {
    let auth = &state.auth;
    // Every session and refresh chain of this subject, in one state-DB
    // transaction; a failure is a 5xx (`AuthError::State`), never a 204 that
    // leaves bearers live.
    let revoked = auth.logout(&identity).await?;
    tracing::debug!(user_sub = %identity.user_sub, revoked, "logout revoked every session and refresh chain");
    Ok(StatusCode::NO_CONTENT)
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            AuthError::MissingBearer
            | AuthError::InvalidSession
            | AuthError::RevokedSession
            | AuthError::ExpiredSession
            | AuthError::Jwt(_) => StatusCode::UNAUTHORIZED,
            AuthError::Discovery
            | AuthError::CodeExchange
            | AuthError::IdToken
            | AuthError::EmailUnverified => StatusCode::BAD_GATEWAY,
            // `HttpClient` is a boot-time failure surface — main bails before
            // serving — so this arm is only reachable if a future caller
            // constructs an `OidcClient` lazily. Treat it as internal.
            AuthError::HttpClient | AuthError::State(_) => StatusCode::INTERNAL_SERVER_ERROR,
            // Store full: gateway is overloaded, client should retry.
            AuthError::StoreFull => StatusCode::SERVICE_UNAVAILABLE,
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
        AuthError::ExpiredSession => ("unauthenticated", "expired_session"),
        AuthError::Discovery => ("internal", "oidc_discovery_failed"),
        AuthError::CodeExchange => ("internal", "oidc_code_exchange_failed"),
        AuthError::IdToken => ("internal", "oidc_id_token_invalid"),
        AuthError::EmailUnverified => ("internal", "oidc_email_unverified"),
        AuthError::HttpClient => ("internal", "oidc_http_client_init_failed"),
        AuthError::State(_) => ("internal", "state_db_error"),
        AuthError::StoreFull => ("overloaded", "auth_store_full"),
    }
}

/// The OAuth error code relayed to an MCP client when the IdP returned none:
/// the two retry signals pass through; everything else (including codes
/// about the gateway's own IdP registration) is `access_denied`.
fn client_facing_idp_error(idp_error: Option<&str>) -> &'static str {
    match idp_error {
        Some("temporarily_unavailable") => "temporarily_unavailable",
        Some("server_error") => "server_error",
        _ => "access_denied",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_retry_signals_pass_through_from_the_idp() {
        assert_eq!(
            client_facing_idp_error(Some("temporarily_unavailable")),
            "temporarily_unavailable"
        );
        assert_eq!(
            client_facing_idp_error(Some("server_error")),
            "server_error"
        );
        for other in [
            Some("access_denied"),
            Some("unauthorized_client"),
            Some("x"),
            None,
        ] {
            assert_eq!(client_facing_idp_error(other), "access_denied", "{other:?}");
        }
    }
}
