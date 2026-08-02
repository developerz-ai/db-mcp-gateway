//! Transport layer: MCP over Streamable HTTP — a single endpoint where `GET`
//! opens the server→client SSE stream and `POST` carries client→server JSON-RPC.
//!
//! Owns framing + auth wiring: JSON-RPC parsing, method dispatch, SSE, and the
//! bearer-auth middleware on /mcp POST. DB execution and audit live elsewhere.
//! See website/docs/initial-idea/02-architecture.md.

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
pub mod limit;
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
pub use oauth_state::{AuthCodes, DEFAULT_REFRESH_TTL, GrantIdentity, PendingFlows, RefreshTokens};

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
    let limiter = Arc::new(limit::ConcurrencyLimiter::with_caps(
        config.max_concurrent_requests,
        config.max_concurrent_per_identity,
    ));
    let gated = Router::new()
        .route(&path, post(post_handler))
        .route("/auth/logout", post(auth_routes::logout))
        .route_layer(middleware::from_fn_with_state(
            limiter.clone(),
            limit::enforce,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::bearer_auth,
        ));

    // RFC 9728 §3.1: clients may key the protected-resource metadata by the
    // resource's path, so serve it at both the bare well-known and the
    // `mcp_path`-suffixed well-known (e.g. `/.well-known/oauth-protected-resource/mcp`).
    let prm_suffixed = format!("/.well-known/oauth-protected-resource{path}");

    // Genuinely open: k8s probes + Prometheus scraper (unauthenticated by
    // design — no bearer to check) and OAuth/OIDC discovery metadata (public
    // by spec, read-only, cheap to serve). Deliberately NOT concurrency-limited
    // — probes are trusted infra traffic and discovery documents are static.
    let probes_and_metadata = Router::new()
        .route(&path, get(sse::handler))
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
        .route("/healthz", get(probes::healthz))
        .route("/readyz", get(probes::readyz))
        .route("/metrics", get(probes::metrics));

    // Open (no bearer — that's the point, these run BEFORE a session exists)
    // but still concurrency-limited: each of these writes into an in-memory,
    // size-capped store (`PendingFlows`, `AuthCodes`) or does IdP/DB work, so
    // an unauthenticated flood must be bounded the same way authenticated
    // traffic is (#136 audit: "/authorize flood wedges all logins" — this
    // router previously skipped `limit::enforce` entirely). Global cap only
    // in practice: `limit::enforce` degrades to global-only when no
    // `Identity` extension is present, which is always true here.
    let oauth_flow = Router::new()
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/callback", get(auth_routes::callback))
        // MCP OAuth bridge (RFC 9728 / 8414 / 7591 + PKCE). These let
        // spec-compliant clients (Claude Code, …) discover + complete OAuth
        // with no manual credential wiring. See `transport::oauth`.
        .route("/authorize", get(oauth::authorize))
        .route("/token", post(oauth::token))
        // RFC 7009 token revocation. Unauthenticated like /token — the presented
        // token is itself the credential; you can only revoke one you hold.
        .route("/revoke", post(oauth::revoke))
        .route("/register", post(oauth::register))
        .route_layer(middleware::from_fn_with_state(
            limiter.clone(),
            limit::enforce,
        ));

    let mut router = probes_and_metadata
        .merge(oauth_flow)
        .merge(gated)
        .with_state(state.clone());

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
        let max_session_age = admin_cfg
            .session_max_age_secs
            .map(std::time::Duration::from_secs);
        let admin_router = admin::router(
            admin_cfg.group.clone(),
            repo,
            state_db,
            state.permissions_cache.clone(),
            max_session_age,
        );
        let admin_gated = admin_router.route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::bearer_auth,
        ));
        router = router.merge(admin_gated);
    }

    Ok(router)
}

/// Build a minimal router for protocol-only testing (no bearer auth required).
///
/// **Test use only.** Gated behind the `test-support` feature so the
/// auth-bypassing harness never reaches the default public surface; this
/// crate's own integration tests opt in via the self dev-dependency in
/// `Cargo.toml`. Skips the bearer_auth middleware, so requests don't need a
/// valid bearer token.
#[cfg(feature = "test-support")]
pub fn test_router(config: &Config, state: AppState) -> Router {
    let path = normalize_path(&config.mcp_path);

    // MCP endpoints without bearer auth for protocol-only tests.
    Router::new()
        .route(&path, post(post_handler))
        .route(&path, get(sse::handler))
        .with_state(state)
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
            let id = request.id.response_id();
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
        // Unlike other JSON-RPC methods, `tools/call` has no notification
        // form in the MCP spec — it always runs a DB query whose result (or
        // authz/execution error) only reaches the caller via the response
        // body. A client that omits `id` can never observe the outcome, so
        // executing anyway just means running a real query nobody can see
        // the result of (#136 audit: was silently executed and audited under
        // a synthetic "null" id). Decline before touching config/registry/DB.
        if request.id.is_notification() {
            tracing::warn!(
                %user_sub,
                "tools/call sent as a notification (no id); declining without executing"
            );
            return StatusCode::ACCEPTED.into_response();
        }
        // MCP requires a non-null id on requests. An explicit `"id": null` is
        // neither a valid request nor a notification, so we surface it as
        // invalid_request without executing — same reasoning as the
        // notification branch above (no observable outcome, no audit row).
        if request.id.is_null() {
            tracing::warn!(
                %user_sub,
                r#"tools/call sent with "id": null; rejecting as invalid_request"#
            );
            return Json(jsonrpc::Response::error(
                Value::Null,
                jsonrpc::ErrorObject::invalid_request(),
            ))
            .into_response();
        }
        // MCP `RequestId` is `string | number` (integer). Booleans, arrays,
        // objects, and fractional numbers are still parsed into `Present`,
        // but the tools path must reject them for the same reason as null —
        // there is no correct query/audit outcome for a non-conforming id.
        // Echo the original id so the client can correlate the failure.
        if request.id.is_invalid_type() {
            tracing::warn!(
                %user_sub,
                "tools/call sent with an unsupported id type; rejecting as invalid_request"
            );
            return Json(jsonrpc::Response::error(
                request.id.response_id(),
                jsonrpc::ErrorObject::invalid_request(),
            ))
            .into_response();
        }
        let id = request.id.response_id();
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
        return Json(response).into_response();
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
