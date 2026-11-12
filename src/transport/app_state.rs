//! Process-wide state shared with every request handler, split by audience:
//! [`McpState`] is what tool dispatch and the admin API read, [`OAuthState`]
//! is what the login / OAuth-bridge / bearer-auth handlers read. Handlers
//! extract only their half (`State<McpState>`, `State<OAuthState>`) through
//! the derived `FromRef`.
//!
//! Every dependency is required: the binary wires real ones in
//! `startup::boot`, tests wire real or offline ones through
//! [`AppState::for_tests`]. There is no "not configured" branch to forget.

use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::extract::FromRef;
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use super::probes::ReadinessCache;
use crate::audit::drain::DetachedTasks;
use crate::audit::stream::StreamSinks;
use crate::auth::oauth::{AuthFacade, ClientRegistry};
use crate::authz::PermissionsCache;
use crate::config::ConfigFile;
use crate::exec::AdapterRegistry;
use crate::state::permissions::PermissionsRepo;

#[derive(Clone, Debug, FromRef)]
pub struct AppState {
    pub mcp: McpState,
    pub oauth: OAuthState,
    /// The process shutdown token. Cancelled by the signal handler, so
    /// `/healthz` and `/readyz` return 503 while in-flight requests drain.
    pub shutdown: CancellationToken,
    pub readiness: ReadinessCache,
}

/// Data-plane dependencies: tool dispatch on `/mcp` and the admin API.
#[derive(Clone, Debug)]
pub struct McpState {
    /// Loaded YAML config, swapped whole on SIGHUP reload. Load it once per
    /// request: one request sees one snapshot.
    pub config: Arc<ArcSwap<ConfigFile>>,
    /// Per-`(server, database)` adapter registry; opens adapters lazily.
    pub adapter_registry: AdapterRegistry,
    /// Gateway state DB: audit rows, `/readyz`, admin writes.
    pub state_db: PgPool,
    /// Per-user DB-grant cache (#49), invalidated by admin writes.
    pub permissions_cache: PermissionsCache,
    /// Permissions store the admin API reads and writes.
    pub permissions_repo: Arc<dyn PermissionsRepo>,
    /// `logging.stream` sinks, fed each audit row after its durable write;
    /// rebuilt and swapped with the config on reload.
    pub audit_sinks: Arc<ArcSwap<StreamSinks>>,
    /// Detached audit work (fallback writes, sink deliveries); `main` drains
    /// it at shutdown.
    pub detached: DetachedTasks,
}

/// Auth dependencies: login, the MCP OAuth bridge and bearer verification.
#[derive(Clone, Debug)]
pub struct OAuthState {
    pub auth: AuthFacade,
    /// Dynamic-Client-Registration registry: `/authorize` matches the
    /// requested `redirect_uri` against it exactly.
    pub client_registry: ClientRegistry,
    /// Where the MCP endpoint is mounted (e.g. `/mcp`); the discovery
    /// metadata advertises `<base><mcp_path>` as the resource (RFC 8707).
    pub mcp_path: Arc<str>,
}

impl AppState {
    pub fn new(mcp: McpState, oauth: OAuthState, shutdown: CancellationToken) -> Self {
        Self {
            mcp,
            oauth,
            shutdown,
            readiness: ReadinessCache::default(),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl AppState {
    /// Test wiring around `state_db` and `auth`: the production permissions
    /// store (Postgres, over `state_db`), an in-memory client registry, an
    /// empty adapter registry and an uninstalled metrics recorder. Mutate the
    /// public fields for anything else (a MySQL repo, a shared cache).
    pub fn for_tests(config: ConfigFile, state_db: PgPool, auth: AuthFacade) -> Self {
        use std::time::Duration;

        let repo: Arc<dyn PermissionsRepo> = Arc::new(
            crate::state::permissions::pg::PgPermissionsRepo::new(state_db.clone()),
        );
        let cache_ttl =
            Duration::from_secs(crate::config::Config::default().permissions_cache_ttl_seconds);
        let detached = DetachedTasks::new();
        let mcp = McpState {
            audit_sinks: Arc::new(ArcSwap::from_pointee(StreamSinks::from_config(
                &config.logging.stream,
            ))),
            config: Arc::new(ArcSwap::from_pointee(config)),
            adapter_registry: AdapterRegistry::with_detached(detached.clone()),
            state_db,
            permissions_cache: PermissionsCache::new(repo.clone(), cache_ttl)
                .with_detached(detached.clone()),
            permissions_repo: repo,
            detached,
        };
        let oauth = OAuthState {
            auth,
            client_registry: ClientRegistry::default(),
            mcp_path: Arc::from("/mcp"),
        };
        Self::new(mcp, oauth, CancellationToken::new())
    }
}

/// Unit-test state with no reachable database or IdP: the state pool is
/// lazy and points nowhere, so anything touching it fails like an outage.
#[cfg(test)]
pub(crate) fn offline_for_tests() -> AppState {
    use std::time::Duration;

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use crate::auth::oauth::{AuthCodes, PendingFlows, RefreshTokens};
    use crate::auth::{AuthConfig, OidcClient, ServiceTokenStore, SessionStore};

    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(200))
        .connect_lazy_with(PgConnectOptions::new().host("offline.invalid"));
    let auth_config = AuthConfig::default();
    let auth = AuthFacade {
        jwt: crate::auth::jwt::SessionJwt::new(&auth_config.session_signing_key),
        config: Arc::new(auth_config.clone()),
        sessions: SessionStore::new(pool.clone()),
        oidc: OidcClient::new(auth_config).expect("http client builds"),
        flows: PendingFlows::default(),
        codes: AuthCodes::default(),
        refresh: RefreshTokens::default(),
        service_tokens: Arc::new(ArcSwap::from_pointee(ServiceTokenStore::default())),
    };
    let config = ConfigFile::from_yaml_str("servers: []\npermissions: []\n").expect("empty yaml");
    AppState::for_tests(config, pool, auth)
}
