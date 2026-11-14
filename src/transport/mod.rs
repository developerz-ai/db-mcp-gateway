//! Transport layer: MCP over Streamable HTTP — `POST <mcp_path>` carries
//! client→server JSON-RPC; `GET <mcp_path>` is `405` because the gateway
//! never initiates server→client messages (MCP 2025-06-18 allows this).
//!
//! Owns framing + HTTP wiring: request ids, JSON-RPC parsing, method dispatch,
//! bearer auth, concurrency budgets, timeouts, the OAuth bridge, probes and
//! the admin API mount. DB execution and audit live elsewhere.
//! See website/docs/initial-idea/02-architecture.md.

pub mod admin;
pub mod app_state;
pub mod errors;
pub mod limit;
pub mod probes;
pub mod request_id;
pub mod tls;

mod auth_middleware;
mod auth_routes;
mod bounds;
mod dispatch;
mod mcp_handler;
mod mcp_headers;
mod oauth;
mod upstream;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};

pub use app_state::{AppState, McpState, OAuthState};
pub use bounds::MCP_TIMEOUT;
pub use errors::TransportError;

use crate::config::Config;
use bounds::Bounds;
use limit::ConcurrencyLimiter;

/// Build the axum router: the bearer-gated `/mcp` + logout, the OAuth bridge,
/// probes + discovery, and — when `admin.enabled` — `/admin/v1/*`.
///
/// Refuses a zero concurrency cap: a gateway that sheds every request is a
/// misconfiguration, not a mode.
pub fn router(config: &Config, state: AppState) -> Result<Router, TransportError> {
    if config.max_concurrent_requests == 0 || config.max_concurrent_per_identity == 0 {
        return Err(TransportError::ZeroConcurrencyCap);
    }
    let path = normalize_path(&config.mcp_path);

    // Bearer-gated budget, shared by `/mcp`, logout and the admin API. Layer
    // order: the last-applied route layer runs first, so `bearer_auth`
    // resolves the `Identity` before `limit::enforce` reads it.
    let gated_limiter = Arc::new(ConcurrencyLimiter::with_caps(
        config.max_concurrent_requests,
        config.max_concurrent_per_identity,
    ));
    let gated = Router::new()
        .route(&path, post(mcp_handler::post_handler))
        .route("/auth/logout", post(auth_routes::logout))
        .route_layer(middleware::from_fn_with_state(
            gated_limiter.clone(),
            limit::enforce,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.oauth.clone(),
            auth_middleware::bearer_auth,
        ));

    // RFC 9728 §3.1: clients may key the protected-resource metadata by the
    // resource's path, so serve it at both the bare well-known and the
    // `mcp_path`-suffixed well-known (e.g. `/.well-known/oauth-protected-resource/mcp`).
    let prm_suffixed = format!("/.well-known/oauth-protected-resource{path}");

    // Genuinely open and uncapped: k8s probes (trusted infra traffic, no
    // bearer; `/metrics` is on its own listener), the static OAuth/OIDC discovery documents, and the
    // constant `405` for `GET <mcp_path>`.
    let open = Router::new()
        .route(&path, get(mcp_handler::get_not_allowed))
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
        .route("/readyz", get(probes::readyz));

    // Open (these run before a session exists) but bounded by their own,
    // smaller budget: each writes into a size-capped store or does IdP/DB
    // work, and none carries an identity to rate-limit by (#136).
    let oauth_flow = Router::new()
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/callback", get(auth_routes::callback))
        // MCP OAuth bridge (RFC 9728 / 8414 / 7591 / 7009 + PKCE). See
        // `transport::oauth`.
        .route("/authorize", get(oauth::authorize))
        .route(oauth::CONSENT_PATH, post(oauth::consent))
        .route("/token", post(oauth::token))
        .route("/revoke", post(oauth::revoke))
        .route("/register", post(oauth::register))
        .route_layer(middleware::from_fn_with_state(
            Arc::new(ConcurrencyLimiter::unauthenticated(
                config.max_concurrent_requests,
            )),
            limit::enforce,
        ));

    let mut router = Bounds::Open
        .apply(open)
        .merge(Bounds::OAuth.apply(oauth_flow))
        .merge(Bounds::Mcp.apply(gated))
        .with_state(state.clone());

    // Spec 12: with `admin.enabled` false or absent, `/admin/*` stays
    // unmounted (404). Mounted, it is bearer-gated, admin-group-gated (inside
    // `admin::router`) and shares the gated concurrency budget. Read from the
    // boot snapshot: a reload cannot mount, unmount or regroup the admin API.
    let boot_config = state.mcp.config.load_full();
    if let Some(admin_cfg) = boot_config.admin.as_ref()
        && admin_cfg.enabled
    {
        let admin = admin::router(admin::AdminDeps {
            group: admin_cfg.group.clone(),
            repo: state.mcp.permissions_repo.clone(),
            state_db: state.mcp.state_db.clone(),
            cache: state.mcp.permissions_cache.clone(),
            sessions: state.oauth.auth.sessions.clone(),
            max_session_age: admin_cfg.session_max_age_secs.map(Duration::from_secs),
            known_servers: boot_config
                .servers
                .iter()
                .map(|server| server.name.clone())
                .collect(),
        })
        .route_layer(middleware::from_fn_with_state(
            gated_limiter,
            limit::enforce,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.oauth.clone(),
            auth_middleware::bearer_auth,
        ));
        router = router.merge(Bounds::Admin.apply(admin));
    }

    // Outermost, so every response — including 404/405 and every rejection
    // above — carries the request id.
    Ok(router.layer(middleware::from_fn(request_id::assign)))
}

/// Build a minimal router for protocol-only testing (no bearer auth required).
///
/// **Test use only.** Gated behind the `test-support` feature so the
/// auth-bypassing harness never reaches the default public surface; this
/// crate's own integration tests opt in via the self dev-dependency in
/// `Cargo.toml`.
#[cfg(feature = "test-support")]
pub fn test_router(config: &Config, state: AppState) -> Router {
    Router::new()
        .route(
            &normalize_path(&config.mcp_path),
            post(mcp_handler::post_handler),
        )
        .with_state(state)
        .layer(middleware::from_fn(request_id::assign))
}

/// axum routes require a leading slash; tolerate config that omits it.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
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
