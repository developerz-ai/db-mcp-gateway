//! Boot-time construction: logging, the state DB, the permissions store and
//! the `AppState` the router serves.

use std::sync::Arc;
use std::time::Duration;

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
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::transport::AppState;
use db_mcp_gateway::transport::probes::ShutdownFlag;
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Install the global JSON-per-line stdout subscriber for Loki (see
/// docs/deployment/logging.md for the field contract). `flatten_event` hoists
/// `tracing::info!(k = v, …)` fields to the top level so Alloy doesn't need a
/// nested-field stage; spans don't render because every per-request field is
/// also emitted on the event itself. `with_target(true)` preserves the event's
/// `target` — the module path by default, but explicitly set on `audit_stream`
/// events (see `src/audit/stream.rs`) so operators can route the SIEM export
/// separately from operational logs. Dropping it here would silently break the
/// spec 07 §Stream contract.
///
/// Writes go through `tracing_appender::non_blocking` so a slow stdout consumer
/// (a paused terminal, a jammed log pipeline, a full pipe) never blocks the
/// request path — every `tracing::info!` on the hot path, including the
/// `audit_stream` fan-out in `src/audit/stream.rs`, is fire-and-forget. The
/// returned guard MUST live for the lifetime of `run` so the queue drains on
/// shutdown; drop it early and the appender thread exits mid-flight, silently
/// dropping the tail of the audit stream.
pub(crate) fn init_tracing() -> WorkerGuard {
    let (non_blocking_stdout, log_guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .with_writer(non_blocking_stdout)
        .init();
    log_guard
}

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
pub(crate) async fn build_app_state(
    config_file: ConfigFile,
    config: &Config,
    auth_config: AuthConfig,
    service_tokens: ServiceTokenStore,
    metrics_handle: PrometheusHandle,
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
    let permissions_cache = PermissionsCache::new(
        permissions_repo.clone(),
        Duration::from_secs(config.permissions_cache_ttl_seconds),
    );
    // Captured before `auth_config` moves into the facade below.
    let refresh_ttl = auth_config.refresh_ttl;
    Ok(AppState {
        auth: Some(AuthFacade {
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
            service_tokens,
        }),
        config: Arc::new(config_file),
        adapter_registry: AdapterRegistry::new(),
        state_db: Some(state_db.clone()),
        shutdown: ShutdownFlag::new(),
        metrics: Some(metrics_handle),
        permissions_cache: Some(permissions_cache),
        permissions_repo: Some(permissions_repo),
        mcp_path: Arc::from(config.mcp_path.as_str()),
        // Persist DCR registrations in the shared state DB so a restart /
        // redeploy no longer drops them (the `invalid_client` wedge for clients
        // that cache their `client_id`). `default()` — in-memory — is the
        // auth-less test bootstrap only.
        client_registry: ClientRegistry::with_db(state_db.clone()),
    })
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
    let driver = config_file
        .permissions_store
        .as_ref()
        .map(|s| s.driver)
        .unwrap_or(PermissionsStoreDriver::Pg);
    match driver {
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
