//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.

mod sentry_scrub;
mod startup;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use db_mcp_gateway::auth::{
    AuthConfig, OidcClient, ServiceTokenStore, SessionCacheConfig, SessionStore,
};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{ConfigFile, TlsConfig};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::transport::probes::ShutdownFlag;
use db_mcp_gateway::transport::tls;
use db_mcp_gateway::transport::{
    AppState, AuthCodes, AuthFacade, ClientRegistry, PendingFlows, RefreshTokens,
};
use db_mcp_gateway::{config::Config, state, transport};
use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::EnvFilter;

use startup::{
    install_shutdown_signal, spawn_audit_pruner, spawn_oauth_state_gc, spawn_reload_on_sighup,
};

#[derive(Debug, Parser)]
#[command(name = "db-mcp-gateway", version, about)]
struct Cli {
    /// Path to the YAML config file (servers + permissions). Required; spec
    /// 08-config.md says no half-loaded state.
    #[arg(long, env = "DB_MCP_GATEWAY_CONFIG")]
    config: PathBuf,
}

fn main() -> anyhow::Result<()> {
    // GlitchTip/Sentry initializes FIRST, before the tokio runtime exists, so a
    // panic during runtime construction or `run()` is still captured. The guard
    // flushes its send queue on drop — bind it to a named local (never `let _ = …`)
    // so it outlives every path through `main`, including the `Err` returns here
    // and inside `block_on` (drop runs after `block_on` resolves → 2s flush).
    // CLAUDE.md non-negotiable #1: every outgoing event is credential-scrubbed
    // via the before_send hook in `sentry_scrub`.
    let _sentry_guard = sentry_scrub::init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        // Thread-init/resource failures (rare) land here. The sentry client is
        // already initialized above, so route the builder error through the same
        // capture path as `run()` below instead of `?`-returning past it.
        Err(err) => {
            sentry::capture_error(&err);
            return Err(err.into());
        }
    };
    let result = runtime.block_on(run());

    // `run()` returns `Err` for config-load / DB-connect / bind failures. Those
    // are normal returns, not panics, so the sentry `panic` integration never
    // sees them — without this capture they'd reach stderr and never GlitchTip.
    // `anyhow::Error` is `AsRef<dyn StdError>`; the scrubber strips any
    // credential before the event ships (CLAUDE.md non-negotiable #1). The guard
    // flushes on drop after `main` returns.
    if let Err(ref err) = result {
        // `anyhow::Error` has two `AsRef<dyn StdError>` impls (± Send+Sync);
        // bind to the concrete trait object so `capture_error`'s `E` resolves.
        let err_ref: &(dyn std::error::Error + Send + Sync + 'static) = err.as_ref();
        sentry::capture_error(err_ref);
    }
    result
}

async fn run() -> anyhow::Result<()> {
    // JSON-per-line on stdout for Loki (see docs/deployment/logging.md for
    // the field contract). `flatten_event` hoists `tracing::info!(k = v, …)`
    // fields to the top level so Alloy doesn't need a nested-field stage;
    // spans don't render because every per-request field is also emitted on
    // the event itself. `with_target(true)` preserves the event's `target`
    // — the module path by default, but explicitly set on `audit_stream`
    // events (see `src/audit/stream.rs`) so operators can route the SIEM
    // export separately from operational logs. Dropping it here would
    // silently break the spec 07 §Stream contract.
    //
    // Writes go through `tracing_appender::non_blocking` so a slow stdout
    // consumer (a paused terminal, a jammed log pipeline, a full pipe) never
    // blocks the request path — every `tracing::info!` on the hot path,
    // including the `audit_stream` fan-out in `src/audit/stream.rs`, is
    // fire-and-forget. `_log_guard` MUST live for the lifetime of `run` so
    // the queue drains on shutdown; drop it early and the appender thread
    // exits mid-flight, silently dropping the tail of the audit stream.
    let (non_blocking_stdout, _log_guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .with_writer(non_blocking_stdout)
        .init();

    // rustls 0.23 needs an explicit CryptoProvider; install before any TLS
    // path touches `RustlsConfig` (issue #12).
    tls::install_crypto_provider();

    let cli = Cli::parse();

    // Spec 05 §"resolved at config load": `load` parses, validates, AND
    // resolves every ${ENV:…} / ${FILE:…} ref in one shot. A boot abort is a
    // clearer operator signal than the user's first query failing on connect,
    // and folding resolve into the load helper makes it impossible to ship a
    // SIGHUP path that forgets to re-resolve.
    let config_file = ConfigFile::load(&cli.config)?;
    tracing::info!(
        path = %cli.config.display(),
        servers = config_file.servers.len(),
        permissions = config_file.permissions.len(),
        "config loaded; all secret refs resolved"
    );

    // Service tokens (spec 14): resolve every `service_accounts:` ref now so a
    // weak/unresolvable token aborts boot instead of silently rejecting that
    // client's every call. Empty config → empty store → JWT-only auth, the
    // pre-#185 behavior.
    let service_tokens = ServiceTokenStore::from_config(&config_file.service_accounts)?;
    if !config_file.service_accounts.is_empty() {
        tracing::info!(
            service_accounts = config_file.service_accounts.len(),
            "service tokens resolved"
        );
    }

    let config = Config::from_env()?;
    let auth_config = AuthConfig::from_env()?;

    // Install the Prometheus recorder before anything starts emitting metrics.
    // `install_recorder` registers a process-wide global — any later install
    // (e.g. from a test harness sharing the binary) would fail, which is why
    // tests bootstrap with `AppState::for_tests()` (no recorder).
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|err| anyhow::anyhow!("failed to install Prometheus recorder: {err}"))?;

    let state_db = state::connect(&config.state_db.url, config.state_db.pool_size)
        .await
        .map_err(|err| boot_db_error("state DB", err))?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "state DB connected, migrations applied"
    );

    let shutdown = ShutdownFlag::new();
    let sessions = SessionStore::with_cache_config(
        state_db.clone(),
        SessionCacheConfig {
            ttl: std::time::Duration::from_secs(config.session_cache_ttl_seconds),
            ..SessionCacheConfig::default()
        },
    );
    let oidc = OidcClient::new(auth_config.clone())?;
    // Spec 12 §"Storage backends" / #59: pick the permissions repo based on
    // YAML config. Default (None) is the pg path — the permissions tables
    // live in the same state DB as sessions / audit_calls. Mysql opens a
    // separate pool keyed by `PERMISSIONS_DB_DSN`.
    let permissions_repo: std::sync::Arc<dyn db_mcp_gateway::state::permissions::PermissionsRepo> =
        match config_file
            .permissions_store
            .as_ref()
            .map(|s| s.driver)
            .unwrap_or(db_mcp_gateway::config::PermissionsStoreDriver::Pg)
        {
            db_mcp_gateway::config::PermissionsStoreDriver::Pg => {
                Arc::new(PgPermissionsRepo::new(state_db.clone()))
            }
            db_mcp_gateway::config::PermissionsStoreDriver::Mysql => {
                let dsn = std::env::var("PERMISSIONS_DB_DSN").map_err(|_| {
                    anyhow::anyhow!(
                        "permissions_store.driver = mysql requires PERMISSIONS_DB_DSN env"
                    )
                })?;
                let pool = db_mcp_gateway::state::connect_permissions_mysql(
                    &dsn,
                    config.state_db.pool_size,
                )
                .await
                .map_err(|err| boot_db_error("mysql permissions store", err))?;
                tracing::info!(
                    pool_size = config.state_db.pool_size,
                    "mysql permissions store connected, migrations applied"
                );
                Arc::new(db_mcp_gateway::state::permissions::mysql::MysqlPermissionsRepo::new(pool))
            }
        };
    let permissions_cache = PermissionsCache::new(
        permissions_repo.clone(),
        std::time::Duration::from_secs(config.permissions_cache_ttl_seconds),
    );
    // Captured before `auth_config` moves into the facade below.
    let refresh_ttl = auth_config.refresh_ttl;
    let app_state = AppState {
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
        shutdown: shutdown.clone(),
        metrics: Some(metrics_handle),
        permissions_cache: Some(permissions_cache),
        permissions_repo: Some(permissions_repo),
        mcp_path: Arc::from(config.mcp_path.as_str()),
        // Persist DCR registrations in the shared state DB so a restart /
        // redeploy no longer drops them (the `invalid_client` wedge for clients
        // that cache their `client_id`). `default()` — in-memory — is the
        // auth-less test bootstrap only.
        client_registry: ClientRegistry::with_db(state_db.clone()),
    };

    // Fail closed: a release binary must never serve with auth unwired.
    // `bearer_auth` deliberately passes through when `state.auth` is `None`
    // (the test bootstrap relies on it), so the only thing standing between a
    // wiring regression and an unauthenticated DB-query surface is this guard
    // on the production serve path. Integration tests build the router via
    // `transport::router(...)` directly and never reach `main`, so this never
    // trips them (sec qa 2026-06-29 A2).
    if app_state.auth.is_none() {
        anyhow::bail!("refusing to start: AppState.auth is None — auth facade not wired");
    }

    // Spawn the audit retention pruner. Ticks hourly, deletes rows older
    // than `audit_retention_days`. The tokio runtime drops the task on
    // graceful shutdown — DELETE is the only DB call, so cancelling
    // mid-flight just rolls back; no half-state.
    spawn_audit_pruner(state_db, config.audit_retention_days);

    // Spawn the OAuth state garbage collector. Ticks every 30 seconds to
    // remove expired authorization codes, pending flows, and refresh tokens.
    // This prevents unbounded memory growth from abandoned logins or leaked
    // tokens.
    if let Some(auth_facade) = app_state.auth.as_ref() {
        spawn_oauth_state_gc(
            auth_facade.flows.clone(),
            auth_facade.codes.clone(),
            auth_facade.refresh.clone(),
        );
    }

    let app = transport::router(&config, app_state)?;

    let handle = axum_server::Handle::new();
    let shutdown_for_signal = shutdown.clone();
    let handle_for_signal = handle.clone();
    // Install signal handlers synchronously so a registration failure aborts
    // boot instead of leaving the server unable to drain on `docker stop`.
    let signal_fut = install_shutdown_signal(shutdown_for_signal)?;
    tokio::spawn(async move {
        signal_fut.await;
        // Drain in-flight requests, then close idle. The 30s window matches
        // the upper bound on `statement_timeout` defaults; longer queries get
        // SIGTERM-killed when the runtime tears down.
        handle_for_signal.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    match config.tls.clone() {
        TlsConfig::Enabled {
            cert_path,
            key_path,
        } => {
            let rustls = tls::load(&cert_path, &key_path).await?;
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                addr = %config.bind,
                path = %config.mcp_path,
                cert_path = %cert_path.display(),
                "db-mcp-gateway listening (TLS)"
            );
            // Install the SIGHUP cert hot-reload handler; a registration
            // failure fails boot rather than silently disabling `kill -HUP`.
            spawn_reload_on_sighup(rustls.clone(), cert_path, key_path)?;
            axum_server::bind_rustls(config.bind, rustls)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        TlsConfig::Disabled => {
            tracing::warn!(
                addr = %config.bind,
                "TLS disabled — serving plain HTTP. This is dev-only; never deploy without TLS."
            );
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                addr = %config.bind,
                path = %config.mcp_path,
                "db-mcp-gateway listening (plain HTTP)"
            );
            axum_server::bind(config.bind)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
    }

    Ok(())
}

/// Collapse a boot-time database bring-up failure into a credential-free error.
///
/// `StateDbError::Connect` wraps a `sqlx::Error` whose `Display` can embed the
/// DSN — and therefore the password — when the URL is malformed or auth is
/// rejected. `main` returns `anyhow::Result`, and a returned error is rendered
/// to stderr through its source chain on process exit, so propagating that
/// `#[source]` would print the credential. We log the error *type* only (same
/// discipline as the admin handlers in `transport/admin/`) and return a
/// source-free error. `Migrate` failures name only migration versions, never
/// credentials, so they're surfaced in full for operator debugging. CLAUDE.md
/// non-negotiable #1.
fn boot_db_error(store: &'static str, err: state::StateDbError) -> anyhow::Error {
    match err {
        state::StateDbError::Connect(source) => {
            tracing::error!(
                store,
                error_type = std::any::type_name_of_val(&source),
                "boot database bring-up failed at connect"
            );
            anyhow::anyhow!("{store}: failed to connect (see logs; DSN withheld)")
        }
        state::StateDbError::Migrate(source) => {
            anyhow::Error::new(source).context(format!("{store}: migrations failed"))
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    /// `--config` is required user-facing behavior. Cover the full contract in
    /// one test so we don't race on the shared `DB_MCP_GATEWAY_CONFIG` env var
    /// (clap reads it from the process env at parse time).
    #[test]
    fn cli_parses_required_config_with_env_fallback() {
        const ENV: &str = "DB_MCP_GATEWAY_CONFIG";

        // Baseline: nothing set, no flag → parse fails (required arg).
        // SAFETY: this test is the sole touch-point for $ENV in the bin
        // test binary; no other test reads or writes it.
        unsafe {
            std::env::remove_var(ENV);
        }
        assert!(
            Cli::try_parse_from(["db-mcp-gateway"]).is_err(),
            "missing --config and env var must fail parse"
        );

        // Flag-only path: PathBuf comes from argv.
        let cli = Cli::try_parse_from(["db-mcp-gateway", "--config", "/tmp/flag.yaml"])
            .expect("flag-only parse succeeds");
        assert_eq!(cli.config, PathBuf::from("/tmp/flag.yaml"));

        // Env fallback: no flag, but $ENV set → that value wins.
        unsafe {
            std::env::set_var(ENV, "/tmp/from-env.yaml");
        }
        let cli = Cli::try_parse_from(["db-mcp-gateway"]).expect("env fallback parse succeeds");
        assert_eq!(cli.config, PathBuf::from("/tmp/from-env.yaml"));

        // Precedence: explicit flag beats env.
        let cli = Cli::try_parse_from(["db-mcp-gateway", "--config", "/tmp/flag-wins.yaml"])
            .expect("flag+env parse succeeds");
        assert_eq!(cli.config, PathBuf::from("/tmp/flag-wins.yaml"));

        unsafe {
            std::env::remove_var(ENV);
        }
    }
}
