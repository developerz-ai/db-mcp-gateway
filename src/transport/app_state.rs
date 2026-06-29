//! Process-wide state shared with every request handler.
//!
//! Cloned per request — internals are `Arc`-shared so cloning is cheap. Kept in
//! `transport/` because everything here is HTTP-layer plumbing; the auth
//! primitives themselves live under `crate::auth`.
//!
//! `auth = None` is the test bootstrap (no IdP, no state DB needed). The
//! production binary always sets `Some(AuthFacade)`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;

use super::probes::ShutdownFlag;
use crate::auth::{AuthConfig, OidcClient, SessionStore};
use crate::authz::PermissionsCache;
use crate::config::ConfigFile;
use crate::exec::AdapterRegistry;
use crate::state::permissions::PermissionsRepo;

/// `state → nonce` from /auth/login lives here until /auth/callback consumes
/// (and removes) it. TTL-bounded so a wedged login can't accumulate.
const FLOW_TTL: Duration = Duration::from_secs(5 * 60);

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
}

impl AppState {
    /// Test helper: empty config, no auth, no state DB, empty pool registry.
    /// Production code never uses this.
    #[cfg(any(test, debug_assertions))]
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
}

/// Context an MCP OAuth-bridge `/authorize` request stashes across the IdP
/// round-trip. Recovered at `/auth/callback` (keyed by the OIDC `state`) so the
/// gateway can mint an authorization code and 302 back to the *client's* own
/// redirect URI — the loopback Claude Code listens on.
#[derive(Debug, Clone)]
pub struct OAuthBridge {
    /// The MCP client's registered redirect URI (loopback or https).
    pub client_redirect_uri: String,
    /// The MCP client's `state` — echoed back verbatim on the final redirect.
    pub client_state: String,
    /// PKCE challenge (S256). Verified against `code_verifier` at `/token`.
    pub code_challenge: String,
    /// RFC 8707 `resource` the client bound the request to (audit/diagnostics).
    pub resource: Option<String>,
}

#[derive(Clone, Default, Debug)]
pub struct PendingFlows {
    inner: Arc<Mutex<HashMap<String, PendingFlow>>>,
}

#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub nonce: String,
    /// `Some` for an MCP OAuth-bridge login; `None` for the bespoke
    /// `/auth/login` flow that returns the session token as JSON.
    pub bridge: Option<OAuthBridge>,
    expires_at: Instant,
}

impl PendingFlows {
    pub async fn insert(&self, state: String, nonce: String) {
        self.insert_flow(state, nonce, None).await;
    }

    /// Insert a flow carrying MCP OAuth-bridge context (the client redirect /
    /// state / PKCE challenge to honor once the IdP round-trip completes).
    pub async fn insert_bridge(&self, state: String, nonce: String, bridge: OAuthBridge) {
        self.insert_flow(state, nonce, Some(bridge)).await;
    }

    async fn insert_flow(&self, state: String, nonce: String, bridge: Option<OAuthBridge>) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            state,
            PendingFlow {
                nonce,
                bridge,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
    }

    /// Remove and return the pending flow for a given state, if still live.
    pub async fn take(&self, state: &str) -> Option<PendingFlow> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(state)
    }

    fn gc(map: &mut HashMap<String, PendingFlow>) {
        let now = Instant::now();
        map.retain(|_, flow| flow.expires_at > now);
    }
}

/// TTL for a minted authorization code. Codes are one-time and redeemed
/// immediately by the client, so this is deliberately tight (OAuth 2.1
/// recommends ≤ 10 min; we use 1).
const CODE_TTL: Duration = Duration::from_secs(60);

/// One-time authorization codes for the MCP OAuth bridge. A code maps to the
/// already-issued session bearer plus the PKCE challenge to verify at `/token`.
#[derive(Clone, Default, Debug)]
pub struct AuthCodes {
    inner: Arc<Mutex<HashMap<String, AuthCode>>>,
}

#[derive(Debug, Clone)]
pub struct AuthCode {
    /// The gateway session JWT handed back as the OAuth `access_token`.
    pub access_token: String,
    /// Seconds until the session expires — surfaced as `expires_in`.
    pub expires_in_seconds: u64,
    /// PKCE S256 challenge the redeeming `code_verifier` must satisfy.
    pub code_challenge: String,
    /// Redirect URI from `/authorize`; `/token` must present the same value.
    pub redirect_uri: String,
    expires_at: Instant,
}

impl AuthCodes {
    pub async fn insert(
        &self,
        code: String,
        access_token: String,
        expires_in_seconds: u64,
        code_challenge: String,
        redirect_uri: String,
    ) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            code,
            AuthCode {
                access_token,
                expires_in_seconds,
                code_challenge,
                redirect_uri,
                expires_at: Instant::now() + CODE_TTL,
            },
        );
    }

    /// Remove and return a code (one-time use), if still live.
    pub async fn take(&self, code: &str) -> Option<AuthCode> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(code)
    }

    fn gc(map: &mut HashMap<String, AuthCode>) {
        let now = Instant::now();
        map.retain(|_, code| code.expires_at > now);
    }
}
