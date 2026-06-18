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
    /// Per-`(server, database)` target Postgres pools. Lazy.
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
            }),
            adapter_registry: AdapterRegistry::new(),
            state_db: None,
            shutdown: ShutdownFlag::new(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthFacade {
    pub config: Arc<AuthConfig>,
    pub sessions: SessionStore,
    pub oidc: OidcClient,
    pub flows: PendingFlows,
}

#[derive(Clone, Default, Debug)]
pub struct PendingFlows {
    inner: Arc<Mutex<HashMap<String, PendingFlow>>>,
}

#[derive(Debug, Clone)]
struct PendingFlow {
    nonce: String,
    expires_at: Instant,
}

impl PendingFlows {
    pub async fn insert(&self, state: String, nonce: String) {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.insert(
            state,
            PendingFlow {
                nonce,
                expires_at: Instant::now() + FLOW_TTL,
            },
        );
    }

    /// Remove and return the nonce for a given state, if still live.
    pub async fn take(&self, state: &str) -> Option<String> {
        let mut map = self.inner.lock().await;
        Self::gc(&mut map);
        map.remove(state).map(|flow| flow.nonce)
    }

    fn gc(map: &mut HashMap<String, PendingFlow>) {
        let now = Instant::now();
        map.retain(|_, flow| flow.expires_at > now);
    }
}
