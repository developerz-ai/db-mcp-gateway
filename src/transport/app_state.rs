//! Process-wide state shared with every request handler.
//!
//! Cloned per request — internals are `Arc`-shared so cloning is cheap. Kept in
//! `transport/` because everything here is HTTP-layer plumbing; the auth
//! primitives themselves live under `crate::auth`.
//!
//! `auth = None` is the test bootstrap (no IdP, no state DB needed). The
//! production binary always sets `Some(AuthFacade)`.

use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use super::client_registry::ClientRegistry;
use super::oauth_state::{AuthCodes, PendingFlows, RefreshTokens};
use super::probes::ShutdownFlag;
use crate::auth::{AuthConfig, OidcClient, SessionStore};
use crate::authz::PermissionsCache;
use crate::config::ConfigFile;
use crate::exec::AdapterRegistry;
use crate::state::permissions::PermissionsRepo;

#[derive(Clone, Debug)]
pub struct AppState {
    pub auth: Option<AuthFacade>,
    /// Loaded `servers:` + `permissions:` from the YAML config. Empty when
    /// tests don't care about tool dispatch.
    pub config: Arc<ConfigFile>,
    /// Per-`(server, database)` `DbAdapter` registry. Lazy; opens the
    /// backend-specific adapter (today only `PgAdapter`) on first use.
    pub adapter_registry: AdapterRegistry,
    /// Gateway's own state DB. Tools that audit (`run_query`) need it; tests
    /// that only exercise the wire protocol leave it `None`.
    pub state_db: Option<PgPool>,
    /// Flipped by the graceful-shutdown handler so `/healthz` and `/readyz`
    /// return 503 while in-flight requests drain.
    pub shutdown: ShutdownFlag,
    /// Prometheus recorder handle. `None` in tests — installing the recorder
    /// is a process-wide singleton and would clash across test binaries.
    pub metrics: Option<PrometheusHandle>,
    /// Per-user DB-grant cache (#49). `None` in tests that don't exercise the
    /// resolver — dispatch falls through to YAML-only authz, which is the
    /// same path the gateway took before #49.
    pub permissions_cache: Option<PermissionsCache>,
    /// Permissions store handle. `Some` whenever the admin API (#52) is
    /// mounted; the admin handlers read/write through this. The cache uses
    /// its own clone so cache-only paths don't need the repo in `AppState`.
    /// `None` in tests that don't exercise the admin surface.
    pub permissions_repo: Option<Arc<dyn PermissionsRepo>>,
    /// The path the MCP endpoint is mounted at (e.g. `/mcp`), copied from the
    /// runtime `Config`. The OAuth metadata handlers need it to advertise the
    /// canonical resource URI (`<base><mcp_path>`) per RFC 8707.
    pub mcp_path: Arc<str>,
    /// Dynamic-Client-Registration registry: `client_id` → registered redirect
    /// URIs. `/authorize` matches the requested `redirect_uri` against this set
    /// exactly (OAuth 2.1 redirect allowlist). Always present and independent of
    /// `auth`, so `/register` persists even on the auth-less test bootstrap.
    pub client_registry: ClientRegistry,
}

impl AppState {
    /// Test helper: empty config, no auth, no state DB, empty pool registry.
    /// Production code never uses this.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self {
            auth: None,
            config: Arc::new(ConfigFile {
                servers: Vec::new(),
                permissions: Vec::new(),
                admin: None,
                permissions_store: None,
            }),
            adapter_registry: AdapterRegistry::new(),
            state_db: None,
            shutdown: ShutdownFlag::new(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
            mcp_path: Arc::from("/mcp"),
            client_registry: ClientRegistry::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthFacade {
    pub config: Arc<AuthConfig>,
    pub sessions: SessionStore,
    pub oidc: OidcClient,
    pub flows: PendingFlows,
    /// One-time authorization codes minted by the MCP OAuth bridge
    /// (`/authorize` → IdP → `/auth/callback` → here), redeemed at `/token`.
    /// Unused by the bespoke `/auth/login` JSON flow.
    pub codes: AuthCodes,
    /// Long-lived refresh tokens minted alongside each bridge access token, so
    /// MCP clients can silently renew an expired session without a fresh
    /// browser login. Rotated on every use (OAuth 2.1 public-client rule).
    pub refresh: RefreshTokens,
}
