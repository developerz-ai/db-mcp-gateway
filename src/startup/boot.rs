//! Boot-time construction: the permissions store, its listener and the
//! `AppState` the router serves.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::audit::stream::StreamSinks;
use db_mcp_gateway::auth::jwt::SessionJwt;
use db_mcp_gateway::auth::oauth::{
    AuthCodes, AuthFacade, ClientRegistry, PendingFlows, RefreshTokens,
};
use db_mcp_gateway::auth::{
    AuthConfig, LoginOptions, OidcClient, ServiceTokenStore, SessionCacheConfig, SessionStore,
};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{Config, ConfigFile, PermissionsStoreDriver};
use db_mcp_gateway::exec::{AdapterRegistry, pg};
use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::mysql::MysqlPermissionsRepo;
use db_mcp_gateway::state::permissions::pg::{PgPermissionsRepo, notify};
use db_mcp_gateway::transport::{AppState, McpState, OAuthState};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

use super::{Shutdown, metrics};

/// Wire every `AppState` dependency. Moves `config_file` and `auth_config` in.
/// Probes go 503 at `shutdown.stop`.
pub(crate) async fn build_app_state(
    config_file: ConfigFile,
    config: &Config,
    auth_config: AuthConfig,
    service_tokens: ServiceTokenStore,
    shutdown: &Shutdown,
    state_db: &PgPool,
) -> anyhow::Result<AppState> {
    let sessions = SessionStore::with_cache_config(
        state_db.clone(),
        SessionCacheConfig {
            ttl: Duration::from_secs(config.session_cache_ttl_seconds),
            ..SessionCacheConfig::default()
        },
    );
    let oidc = OidcClient::with_options(auth_config.clone(), LoginOptions::from_env()?)?;
    // Captured before `auth_config` moves into the facade below.
    let refresh_ttl = auth_config.refresh_ttl;
    // One drain set: detached audit writes and target-side cancels both
    // finish (bounded) before shutdown closes the pools.
    let detached = DetachedTasks::new();
    let (permissions_repo, permissions_cache) =
        build_permissions(&config_file, config, state_db, &detached, shutdown).await?;
    pg::init_cancel_pool_size_from_env()?;
    metrics::preregister::register_targets(&config_file);
    metrics::state_pools::spawn_state_pool_sampler(
        "request",
        state_db.clone(),
        shutdown.finished.clone(),
    );
    let mcp = McpState {
        audit_sinks: Arc::new(ArcSwap::from_pointee(
            StreamSinks::from_config(&config_file.logging.stream)
                .map_err(|e| anyhow::Error::new(e).context("logging.stream: syslog sink"))?,
        )),
        config: Arc::new(ArcSwap::from_pointee(config_file)),
        adapter_registry: AdapterRegistry::with_detached(detached.clone()),
        state_db: state_db.clone(),
        permissions_cache,
        permissions_repo,
        detached,
    };
    // Login state in the shared state DB (migration 0022): no sticky routing.
    let flows = PendingFlows::with_db(state_db.clone(), &auth_config.session_signing_key);
    let oauth = OAuthState {
        auth: AuthFacade {
            jwt: SessionJwt::new(&auth_config.session_signing_key),
            config: Arc::new(auth_config),
            sessions,
            oidc,
            flows,
            codes: AuthCodes::with_db(state_db.clone()),
            // Persist refresh chains in the shared state DB: a chain is meant to
            // outlive the process (that is what `REFRESH_TTL_DAYS` buys), and an
            // in-memory store silently capped the real "stay signed in" window at
            // time-until-next-rollout.
            refresh: RefreshTokens::with_db(state_db.clone(), refresh_ttl),
            service_tokens: Arc::new(ArcSwap::from_pointee(service_tokens)),
        },
        // Persist DCR registrations in the shared state DB so a restart /
        // redeploy no longer drops them (the `invalid_client` wedge for clients
        // that cache their `client_id`).
        client_registry: ClientRegistry::with_db(state_db.clone()),
        mcp_path: Arc::from(config.mcp_path.as_str()),
    };
    let app_state = AppState::new(mcp, oauth, shutdown.stop.clone());
    metrics::probes::probe_state().attach(app_state.clone());
    Ok(app_state)
}

/// Spec 12 §"Storage backends" / #59: the permissions store the YAML selects
/// and the grant cache over it. The default (no `permissions_store:`) is the
/// state DB, with the `LISTEN/NOTIFY` listener on its own pool; MySQL opens a
/// separate pool keyed by `PERMISSIONS_DB_DSN` and relies on the cache TTL;
/// `driver: none` (YAML-only) starts neither a store nor a listener.
async fn build_permissions(
    config_file: &ConfigFile,
    config: &Config,
    state_db: &PgPool,
    detached: &DetachedTasks,
    shutdown: &Shutdown,
) -> anyhow::Result<(Arc<dyn PermissionsRepo>, PermissionsCache)> {
    let ttl = Duration::from_secs(config.permissions_cache_ttl_seconds);
    match config_file.permissions_store_driver() {
        PermissionsStoreDriver::Pg => {
            let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(state_db.clone()));
            let cache = PermissionsCache::new(repo.clone(), ttl).with_detached(detached.clone());
            let listener_db = state::connect_listener(&config.state_db.url)
                .await
                .map_err(|err| boot_db_error("permissions listener", err))?;
            spawn_permissions_listener(listener_db, cache.clone(), shutdown.drained.clone());
            Ok((repo, cache))
        }
        PermissionsStoreDriver::Mysql => {
            let repo = connect_mysql_repo(config, shutdown.finished.clone()).await?;
            let cache = PermissionsCache::new(repo.clone(), ttl).with_detached(detached.clone());
            Ok((repo, cache))
        }
        PermissionsStoreDriver::YamlOnly => {
            // `McpState` requires a repo; this one is never read — the cache
            // has no store and the admin API cannot be enabled in this mode.
            // No listener, no store connection.
            let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(state_db.clone()));
            tracing::info!(
                "permissions_store.driver = none: YAML-only grants, no store or listener"
            );
            Ok((
                repo,
                PermissionsCache::yaml_only().with_detached(detached.clone()),
            ))
        }
    }
}

/// Cross-replica cache invalidation: apply every committed permissions change
/// another replica announces over `LISTEN/NOTIFY`, until the drain ends — a
/// revocation must still bite requests admitted before SIGTERM. Postgres
/// store only — the MySQL store has no such channel and relies on the TTL.
/// `pool` is the listener's own ([`state::connect_listener`]), never the
/// request pool: the `LISTEN` connection is held for the life of the process.
fn spawn_permissions_listener(pool: PgPool, cache: PermissionsCache, stop: CancellationToken) {
    tokio::spawn(async move {
        let listen = notify::listen(pool, move |change| {
            let cache = cache.clone();
            async move { cache.apply(&change).await }
        });
        tokio::select! {
            () = listen => {}
            () = stop.cancelled() => {}
        }
    });
}

async fn connect_mysql_repo(
    config: &Config,
    finished: CancellationToken,
) -> anyhow::Result<Arc<dyn PermissionsRepo>> {
    let dsn = std::env::var("PERMISSIONS_DB_DSN").map_err(|_| {
        anyhow::anyhow!("permissions_store.driver = mysql requires PERMISSIONS_DB_DSN env")
    })?;
    let pool = state::connect_permissions_mysql(&dsn, config.state_db.pool_size)
        .await
        .map_err(|err| boot_db_error("mysql permissions store", err))?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "mysql permissions store connected, migrations applied"
    );
    metrics::state_pools::spawn_state_pool_sampler("permissions_mysql", pool.clone(), finished);
    Ok(Arc::new(MysqlPermissionsRepo::new(pool)))
}

/// Collapse a boot-time database bring-up failure into a credential-free error.
///
/// `StateDbError::Connect` wraps a `sqlx::Error` whose `Display` can embed the
/// DSN — and therefore the password — when the URL is malformed or auth is
/// rejected. `main` returns `anyhow::Result`, and a returned error is rendered
/// to stderr through its source chain on process exit, so propagating that
/// `#[source]` would print the credential. We log the error *type* plus the
/// credential-free class from [`state::connect_error_class`] (same discipline
/// as the admin handlers in `transport/admin/`) and return a source-free error
/// that names the class — `error_type` alone is the constant
/// `sqlx_core::error::Error`, so it told the operator nothing and made every
/// distinct boot failure one indistinguishable GlitchTip issue. The class
/// travels in the returned message for exactly that reason. `Migrate` failures
/// name only migration versions, never credentials, so they're surfaced in full
/// for operator debugging. CLAUDE.md non-negotiable #1.
pub(super) fn boot_db_error(store: &'static str, err: state::StateDbError) -> anyhow::Error {
    match err {
        state::StateDbError::Connect(source) => {
            let class = state::connect_error_class(&source);
            tracing::error!(
                store,
                error_type = std::any::type_name_of_val(&source),
                error_class = %class,
                "boot database bring-up failed at connect"
            );
            anyhow::anyhow!("{store}: failed to connect ({class}; DSN withheld)")
        }
        state::StateDbError::Migrate(source) => {
            anyhow::Error::new(source).context(format!("{store}: migrations failed"))
        }
    }
}
