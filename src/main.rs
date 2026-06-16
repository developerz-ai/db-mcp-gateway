//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use db_mcp_gateway::audit;
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{ConfigFile, TlsConfig};
use db_mcp_gateway::exec::PoolRegistry;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::transport::probes::ShutdownFlag;
use db_mcp_gateway::transport::tls;
use db_mcp_gateway::transport::{AppState, AuthFacade, PendingFlows};
use db_mcp_gateway::{config::Config, state, transport};
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::PgPool;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "db-mcp-gateway", version, about)]
struct Cli {
    /// Path to the YAML config file (servers + permissions). Required; spec
    /// 08-config.md says no half-loaded state.
    #[arg(long, env = "DB_MCP_GATEWAY_CONFIG")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // JSON-per-line on stdout for Loki (see docs/deployment/logging.md for
    // the field contract). `flatten_event` hoists `tracing::info!(k = v, …)`
    // fields to the top level so Alloy doesn't need a nested-field stage;
    // `with_target(false)` drops the noisy module path; spans don't render
    // because every per-request field is also emitted on the event itself.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
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

    let config = Config::from_env()?;
    let auth_config = AuthConfig::from_env()?;

    // Install the Prometheus recorder before anything starts emitting metrics.
    // `install_recorder` registers a process-wide global — any later install
    // (e.g. from a test harness sharing the binary) would fail, which is why
    // tests bootstrap with `AppState::for_tests()` (no recorder).
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|err| anyhow::anyhow!("failed to install Prometheus recorder: {err}"))?;

    let state_db = state::connect(&config.state_db.url, config.state_db.pool_size).await?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "state DB connected, migrations applied"
    );

    let shutdown = ShutdownFlag::new();
    let sessions = SessionStore::new(state_db.clone());
    let oidc = OidcClient::new(auth_config.clone())?;
    let permissions_cache = PermissionsCache::new(
        Arc::new(PgPermissionsRepo::new(state_db.clone())),
        std::time::Duration::from_secs(config.permissions_cache_ttl_seconds),
    );
    let app_state = AppState {
        auth: Some(AuthFacade {
            config: Arc::new(auth_config),
            sessions,
            oidc,
            flows: PendingFlows::default(),
        }),
        config: Arc::new(config_file),
        pool_registry: PoolRegistry::new(),
        state_db: Some(state_db.clone()),
        shutdown: shutdown.clone(),
        metrics: Some(metrics_handle),
        permissions_cache: Some(permissions_cache),
    };

    // Spawn the audit retention pruner. Ticks hourly, deletes rows older
    // than `audit_retention_days`. The tokio runtime drops the task on
    // graceful shutdown — DELETE is the only DB call, so cancelling
    // mid-flight just rolls back; no half-state.
    spawn_audit_pruner(state_db, config.audit_retention_days);

    let app = transport::router(&config, app_state);

    let handle = axum_server::Handle::new();
    let shutdown_for_signal = shutdown.clone();
    let handle_for_signal = handle.clone();
    tokio::spawn(async move {
        shutdown_signal(shutdown_for_signal).await;
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
            // Hot-reload runs forever; abort when the server stops.
            tokio::spawn(reload_on_sighup(rustls.clone(), cert_path, key_path));
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

/// SIGHUP loop: every signal, re-read cert+key from the configured paths and
/// hand them to the running `RustlsConfig`. Reload failure is logged loudly
/// but never crashes the gateway — the old cert keeps serving until the next
/// signal succeeds. Runs in its own task because `tokio::signal::unix::signal`
/// is a long-lived stream.
#[cfg(unix)]
async fn reload_on_sighup(
    rustls: axum_server::tls_rustls::RustlsConfig,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(error) => {
            tracing::error!(%error, "failed to install SIGHUP handler — cert hot-reload disabled");
            return;
        }
    };
    while hup.recv().await.is_some() {
        match tls::reload(&rustls, &cert_path, &key_path).await {
            Ok(()) => tracing::info!(
                cert_path = %cert_path.display(),
                "TLS certificate reloaded"
            ),
            Err(error) => tracing::error!(
                %error,
                cert_path = %cert_path.display(),
                "TLS certificate reload failed; keeping previous cert"
            ),
        }
    }
}

#[cfg(not(unix))]
async fn reload_on_sighup(
    _rustls: axum_server::tls_rustls::RustlsConfig,
    _cert_path: std::path::PathBuf,
    _key_path: std::path::PathBuf,
) {
    // SIGHUP doesn't exist outside Unix; deployment targets are Linux only.
    std::future::pending::<()>().await;
}

/// Background task: tick hourly and prune any audit row older than the
/// configured TTL. The task is detached — `tokio::time::interval` survives
/// missed ticks (DelayBehavior) and the runtime cancels it on graceful
/// shutdown, which is safe because the only DB write is a single DELETE.
fn spawn_audit_pruner(pool: PgPool, ttl_days: u32) {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match audit::pruner::run_once(&pool, ttl_days).await {
                Ok(0) => tracing::debug!("audit pruner: no expired rows"),
                Ok(n) => tracing::info!(rows = n, ttl_days, "pruned old audit rows"),
                Err(err) => tracing::error!(%err, "audit pruner run failed"),
            }
        }
    });
}

/// Resolve when the process receives Ctrl-C or (on Unix) SIGTERM, so containers
/// drain cleanly on `docker stop`. Flips `shutdown` *before* axum starts
/// draining, so `/healthz` and `/readyz` go 503 in time for k8s to pull the
/// pod out of the Service endpoint set.
async fn shutdown_signal(shutdown: ShutdownFlag) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            // Handler install failed — don't let this resolve, or `select!` would
            // shut the server down without any real signal.
            tracing::error!(%error, "failed to install Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    shutdown.trigger();
    tracing::info!("shutdown signal received");
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
