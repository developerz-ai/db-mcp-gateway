//! Transport layer: MCP over Streamable HTTP — a single endpoint where `GET`
//! opens the server→client SSE stream and `POST` carries client→server JSON-RPC.
//!
//! Owns framing + auth wiring: JSON-RPC parsing, method dispatch, SSE, and the
//! bearer-auth middleware on /mcp POST. DB execution and audit live elsewhere.
//! See docs/initial-idea/02-architecture.md.

pub mod admin;
pub mod app_state;
pub mod errors;
pub mod jsonrpc;
pub mod probes;
pub mod protocol;
pub mod tls;

mod auth_middleware;
mod auth_routes;
mod client_registry;
mod dispatch;
mod limit;
mod oauth;
mod oauth_state;
mod sse;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, header};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::Value;

pub use app_state::{AppState, AuthFacade};
pub use client_registry::ClientRegistry;
pub use errors::TransportError;
pub use oauth_state::{AuthCodes, GrantIdentity, PendingFlows, RefreshTokens};

use crate::auth::Identity;
use crate::config::Config;
use crate::tools;

/// Build the axum router, mounting the MCP endpoint and the auth routes.
///
/// Returns `Err` when the runtime state can't satisfy the configured router —
/// e.g. `admin.enabled = true` but `permissions_repo` / `state_db` are absent
/// from `AppState`. Previously these wiring gaps silently dropped the
/// `/admin/*` surface; now they refuse boot per spec 08 §"no half-loaded state".
pub fn router(config: &Config, state: AppState) -> Result<Router, TransportError> {
    let path = normalize_path(&config.mcp_path);

    // Bearer-gated routes: /mcp POST and /auth/logout (needs a session to
    // revoke). SSE GET and /auth/{login,callback} stay open.
    //
    // Layer order matters: the last-applied layer is outermost (runs first), so
    // `bearer_auth` runs before `limit::enforce` and the per-identity limiter
    // sees the resolved `Identity`. The global cap sheds saturation with 503;
    // the per-identity cap returns 429 (sec qa 2026-06-29 T1).
    let limiter = Arc::new(limit::ConcurrencyLimiter::new());
    let gated = Router::new()
        .route(&path, post(post_handler))
        .route("/auth/logout", post(auth_routes::logout))
        .route_layer(middleware::from_fn_with_state(limiter, limit::enforce))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::bearer_auth,
        ));

    // RFC 9728 §3.1: clients may key the protected-resource metadata by the
    // resource's path, so serve it at both the bare well-known and the
    // `mcp_path`-suffixed well-known (e.g. `/.well-known/oauth-protected-resource/mcp`).
    let prm_suffixed = format!("/.well-known/oauth-protected-resource{path}");

    let open = Router::new()
        .route(&path, get(sse::handler))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/callback", get(auth_routes::callback))
        // MCP OAuth bridge (RFC 9728 / 8414 / 7591 + PKCE). These let
        // spec-compliant clients (Claude Code, …) discover + complete OAuth
        // with no manual credential wiring. See `transport::oauth`.
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::protected_resource_metadata),
        )
        .route(&prm_suffixed, get(oauth::protected_resource_metadata))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::authorization_server_metadata),
        )
        // Alias for clients that only probe OIDC discovery.
        .route(
            "/.well-known/openid-configuration",
            get(oauth::authorization_server_metadata),
        )
        .route("/authorize", get(oauth::authorize))
        .route("/token", post(oauth::token))
        // RFC 7009 token revocation. Unauthenticated like /token — the presented
        // token is itself the credential; you can only revoke one you hold.
        .route("/revoke", post(oauth::revoke))
        .route("/register", post(oauth::register))
        // Ops endpoints: k8s probes + Prometheus scraper. Unauthenticated by
        // design — probes don't carry a bearer, and exposed bodies are
        // generic strings + Prometheus exposition only (no DB internals).
        .route("/healthz", get(probes::healthz))
        .route("/readyz", get(probes::readyz))
        .route("/metrics", get(probes::metrics));

    let mut router = open.merge(gated).with_state(state.clone());

    // Spec 12: when `admin.enabled` is false (or absent), the entire `/admin/*`
    // surface stays unmounted — a request to it returns axum's default 404.
    // The admin router is gated by `bearer_auth` AND `require_admin_group`;
    // unauthenticated callers get 401, non-admin callers get 403.
    if let Some(admin_cfg) = state.config.admin.as_ref()
        && admin_cfg.enabled
    {
        // Fail fast — admin is opted in, so a missing dep is a wiring bug,
        // not a feature toggle. Reporting *which* dep is missing keeps
        // operator diagnosis to one log line.
        let repo = state
            .permissions_repo
            .clone()
            .ok_or(TransportError::AdminDepsMissing {
                missing: "permissions_repo",
            })?;
        let state_db = state
            .state_db
            .clone()
            .ok_or(TransportError::AdminDepsMissing {
                missing: "state_db",
            })?;
        let admin_router = admin::router(
            admin_cfg.group.clone(),
            repo,
            state_db,
            state.permissions_cache.clone(),
        );
        let admin_gated = admin_router.route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::bearer_auth,
        ));
        router = router.merge(admin_gated);
    }

    Ok(router)
}

/// axum routes require a leading slash; tolerate config that omits it.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Handle one client→server JSON-RPC message.
///
/// `Identity` is injected by `auth_middleware::bearer_auth` (or absent in tests
/// that bypass auth). It threads through to the audit layer in a later issue.
async fn post_handler(
    State(state): State<AppState>,
    identity: Option<Extension<Identity>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    let request = match serde_json::from_str::<jsonrpc::Request>(&body) {
        Ok(request) if request.jsonrpc == jsonrpc::JSONRPC_VERSION => request,
        Ok(request) => {
            let id = request.id.unwrap_or(Value::Null);
            return Json(jsonrpc::Response::error(
                id,
                jsonrpc::ErrorObject::invalid_request(),
            ))
            .into_response();
        }
        Err(_) => {
            return Json(jsonrpc::Response::error(
                Value::Null,
                jsonrpc::ErrorObject::parse_error(),
            ))
            .into_response();
        }
    };

    let user_sub = identity
        .as_ref()
        .map(|i| i.user_sub.as_str())
        .unwrap_or("anonymous");
    tracing::debug!(method = %request.method, %user_sub, "mcp request");

    // `tools/call` needs identity + loaded config + pool registry + the
    // request context (IP / agent client) that the audit row records;
    // everything else is pure.
    if request.method == "tools/call" {
        let is_notification = request.id.is_none();
        let id = request.id.clone().unwrap_or(Value::Null);
        let user_agent = headers
            .get(USER_AGENT)
            .or_else(|| headers.get(header::HeaderName::from_static("x-mcp-client")))
            .and_then(|v| v.to_str().ok());
        let request_ctx = tools::RequestContext::from_request(
            connect_info.map(|ConnectInfo(addr)| addr),
            user_agent,
        );
        let response = tools::dispatch_call(
            id,
            identity.as_deref(),
            &state.config,
            &state.adapter_registry,
            state.permissions_cache.as_ref(),
            state.state_db.as_ref(),
            &request_ctx,
            request.params,
        )
        .await;
        return if is_notification {
            StatusCode::ACCEPTED.into_response()
        } else {
            Json(response).into_response()
        };
    }

    match dispatch::dispatch(request) {
        Some(response) => Json(response).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_adds_leading_slash() {
        assert_eq!(normalize_path("mcp"), "/mcp");
        assert_eq!(normalize_path("/mcp"), "/mcp");
    }
}
