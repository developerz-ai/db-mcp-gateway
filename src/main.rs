//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.

mod sentry_scrub;
mod startup;

use std::path::PathBuf;

use clap::Parser;
use db_mcp_gateway::audit::drain::DRAIN_TIMEOUT;
use db_mcp_gateway::auth::{AuthConfig, ServiceTokenStore};
use db_mcp_gateway::config::{Config, ConfigFile, ServerKind, Tls};
use db_mcp_gateway::state;
use db_mcp_gateway::transport::tls;
use tokio_util::sync::CancellationToken;

use startup::{
    AuthGcTargets, build_app_state, connect_state_db, init_logging, install_recorder, serve,
    spawn_audit_pruner, spawn_audit_reaper, spawn_auth_state_gc, spawn_dropped_lines_exporter,
    spawn_metrics_listener,
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
    // via the before_send hook in `sentry_scrub`. `init` compiles the scrubber's
    // patterns up front and fails if this build's `regex` features don't cover
    // them — refuse to boot rather than open an event stream that cannot scrub.
    // `ScrubberError` already names the pattern and the fix, so it needs no
    // context added here.
    let _sentry_guard = sentry_scrub::init()?;

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
    // Bound for the whole of `run` so the non-blocking log queue drains on
    // shutdown — see `init_logging`.
    let (_log_guard, dropped_log_lines) = init_logging()?;

    // rustls 0.23 needs an explicit CryptoProvider; install before any TLS
    // path touches `RustlsConfig` (issue #12).
    tls::install_crypto_provider();

    let cli = Cli::parse();

    // Spec 05 §"resolved at config load": `load` parses, validates, AND
    // resolves every ${ENV:…} / ${FILE:…} ref in one shot. A boot abort is a
    // clearer operator signal than the user's first query failing on connect.
    let config_file = ConfigFile::load(&cli.config)?;
    tracing::info!(
        path = %cli.config.display(),
        servers = config_file.servers.len(),
        permissions = config_file.permissions.len(),
        "config loaded; all secret refs resolved"
    );
    warn_unverified_target_tls(&config_file);

    // Service tokens (spec 14): resolve every `service_accounts:` ref now so a
    // weak/unresolvable token aborts boot instead of silently rejecting that
    // client's every call. Empty config → empty store → JWT-only auth.
    let service_tokens = ServiceTokenStore::from_config(&config_file.service_accounts)?;
    if !config_file.service_accounts.is_empty() {
        tracing::info!(
            service_accounts = config_file.service_accounts.len(),
            "service tokens resolved"
        );
    }

    let config = Config::from_env()?;
    let auth_config = AuthConfig::from_env()?;

    // One token stops everything that is not the request path: background
    // loops, metrics upkeep and listener, the SIGHUP loop. Cancelled by the
    // signal handler, and again below in case `serve` returns on an error.
    let stop = CancellationToken::new();

    // Install the Prometheus recorder before anything starts emitting metrics.
    // `install_recorder` registers a process-wide global — tests bootstrap
    // with no recorder for that reason.
    let metrics_handle = install_recorder(stop.clone())?;
    spawn_metrics_listener(config.metrics_bind, metrics_handle, stop.clone()).await?;
    spawn_dropped_lines_exporter(dropped_log_lines, stop.clone());

    let state_db = connect_state_db(&config).await?;
    // Pruner and GC get their own two connections so a long prune never holds
    // a connection a request is waiting on.
    let background_db = state::connect_background(&config.state_db.url)
        .await
        .map_err(|err| match err {
            // The source can embed the DSN; only its credential-free class escapes.
            state::StateDbError::Connect(source) => anyhow::anyhow!(
                "state DB background pool: failed to connect ({}; DSN withheld)",
                state::connect_error_class(&source)
            ),
            other => anyhow::Error::new(other),
        })?;
    let app_state = build_app_state(
        config_file,
        &config,
        auth_config,
        service_tokens,
        stop.clone(),
        &state_db,
    )
    .await?;

    spawn_audit_pruner(
        background_db.clone(),
        config.audit_retention_days,
        stop.clone(),
    );
    spawn_audit_reaper(background_db.clone(), stop.clone());
    let auth = &app_state.oauth.auth;
    spawn_auth_state_gc(
        AuthGcTargets {
            sessions: auth.sessions.clone(),
            flows: auth.flows.clone(),
            codes: auth.codes.clone(),
            refresh: auth.refresh.clone(),
            client_registry: app_state.oauth.client_registry.clone(),
        },
        stop.clone(),
    );
    // Cloned before `serve` takes the state: the detached audit work must be
    // drained after the listener stops, and the request pool closed after that.
    let detached = app_state.mcp.detached.clone();

    let served = serve(&config, app_state, cli.config.clone(), stop.clone()).await;

    // `serve` returns once the drain window closes. Stop the background loops,
    // let detached audit writes finish (bounded), then close the pools so
    // in-flight state-DB statements complete instead of being cut at exit.
    stop.cancel();
    if let Err(error) = detached.drain(DRAIN_TIMEOUT).await {
        tracing::error!(%error, "detached audit work still running at shutdown; the reaper will mark it abandoned");
    }
    close_pool("background", background_db).await;
    close_pool("request", state_db).await;
    served
}

/// Close a state-DB pool, bounded so a wedged connection cannot hold the pod
/// past its termination grace period.
async fn close_pool(name: &'static str, pool: sqlx::PgPool) {
    const CLOSE_BOUND: std::time::Duration = std::time::Duration::from_secs(10);
    if tokio::time::timeout(CLOSE_BOUND, pool.close())
        .await
        .is_err()
    {
        tracing::warn!(pool = name, "state DB pool did not close within bound");
    }
}

/// Postgres `tls: required` encrypts without verifying the server certificate
/// (`sslmode=require`; Mongo's `required` does verify), and `tls: insecure` is
/// plaintext. Neither should go unnoticed in a deploy log.
fn warn_unverified_target_tls(config_file: &ConfigFile) {
    for server in &config_file.servers {
        match (server.kind, server.tls) {
            (ServerKind::Postgres, Tls::Required) => tracing::warn!(
                server = %server.name,
                "target TLS is encrypted but the server certificate is NOT verified"
            ),
            (_, Tls::Insecure) => tracing::warn!(
                server = %server.name,
                "target TLS is disabled: credentials and results cross the network in plaintext"
            ),
            _ => {}
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
