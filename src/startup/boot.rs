//! Boot-time construction: the state DB, the permissions store and the
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
    AuthConfig, OidcClient, ServiceTokenStore, SessionCacheConfig, SessionStore,
};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{Config, ConfigFile, PermissionsStoreDriver};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::mysql::MysqlPermissionsRepo;
use db_mcp_gateway::state::permissions::pg::{PgPermissionsRepo, notify};
use db_mcp_gateway::transport::{AppState, McpState, OAuthState};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

pub(crate) async fn connect_state_db(config: &Config) -> anyhow::Result<PgPool> {
    let state_db = state::connect(&config.state_db.url, config.state_db.pool_size)
        .await
        .map_err(|err| boot_db_error("state DB", err))?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "state DB connected, migrations applied"
    );
    Ok(state_db)
}

/// Wire every `AppState` dependency. Moves `config_file` and `auth_config` in.
/// `stop` is the process shutdown token; probes go 503 once it is cancelled.
pub(crate) async fn build_app_state(
    config_file: ConfigFile,
    config: &Config,
    auth_config: AuthConfig,
    service_tokens: ServiceTokenStore,
    stop: CancellationToken,
    state_db: &PgPool,
) -> anyhow::Result<AppState> {
    let sessions = SessionStore::with_cache_config(
        state_db.clone(),
        SessionCacheConfig {
            ttl: Duration::from_secs(config.session_cache_ttl_seconds),
            ..SessionCacheConfig::default()
        },
    );
    let oidc = OidcClient::new(auth_config.clone())?;
    let permissions_repo = build_permissions_repo(&config_file, config, state_db).await?;
    // Captured before `auth_config` moves into the facade below.
    let refresh_ttl = auth_config.refresh_ttl;
    // One drain set: detached audit writes and target-side cancels both
    // finish (bounded) before shutdown closes the pools.
    let detached = DetachedTasks::new();
    let permissions_cache = PermissionsCache::new(
        permissions_repo.clone(),
        Duration::from_secs(config.permissions_cache_ttl_seconds),
    )
    .with_detached(detached.clone());
    if permissions_driver(&config_file) == PermissionsStoreDriver::Pg {
        spawn_permissions_listener(state_db.clone(), permissions_cache.clone(), stop.clone());
    }
    let mcp = McpState {
        audit_sinks: Arc::new(ArcSwap::from_pointee(StreamSinks::from_config(
            &config_file.logging.stream,
        ))),
        config: Arc::new(ArcSwap::from_pointee(config_file)),
        adapter_registry: AdapterRegistry::with_detached(detached.clone()),
        state_db: state_db.clone(),
        permissions_cache,
        permissions_repo,
        detached,
    };
    let oauth = OAuthState {
        auth: AuthFacade {
            jwt: SessionJwt::new(&auth_config.session_signing_key),
            config: Arc::new(auth_config),
            sessions,
            oidc,
            flows: PendingFlows::default(),
            codes: AuthCodes::default(),
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
    Ok(AppState::new(mcp, oauth, stop))
}

fn permissions_driver(config_file: &ConfigFile) -> PermissionsStoreDriver {
    config_file
        .permissions_store
        .as_ref()
        .map_or(PermissionsStoreDriver::Pg, |store| store.driver)
}

/// Cross-replica cache invalidation: apply every committed permissions change
/// another replica announces over `LISTEN/NOTIFY`, until shutdown. Postgres
/// store only — the MySQL store has no such channel and relies on the TTL.
/// The listener holds one dedicated connection taken from `pool`.
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

/// Spec 12 §"Storage backends" / #59: pick the permissions repo based on YAML
/// config. Default (None) is the pg path — the permissions tables live in the
/// same state DB as sessions / audit_calls. Mysql opens a separate pool keyed
/// by `PERMISSIONS_DB_DSN`.
async fn build_permissions_repo(
    config_file: &ConfigFile,
    config: &Config,
    state_db: &PgPool,
) -> anyhow::Result<Arc<dyn PermissionsRepo>> {
    match permissions_driver(config_file) {
        PermissionsStoreDriver::Pg => Ok(Arc::new(PgPermissionsRepo::new(state_db.clone()))),
        PermissionsStoreDriver::Mysql => {
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
            Ok(Arc::new(MysqlPermissionsRepo::new(pool)))
        }
    }
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
fn boot_db_error(store: &'static str, err: state::StateDbError) -> anyhow::Error {
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
