//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.
//! Every other mode (`--check`, `--healthcheck`, the operator subcommands) is
//! dispatched to `cli` before any of that starts.

mod cli;
mod sentry_scrub;
mod startup;

use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use db_mcp_gateway::auth::{AuthConfig, ServiceTokenStore};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::state;
use db_mcp_gateway::transport::tls;

use startup::{
    AuthGcTargets, Shutdown, build_app_state, connect_state_db, init_logging, install_recorder,
    serve, spawn_audit_pruner, spawn_audit_reaper, spawn_auth_state_gc,
    spawn_dropped_lines_exporter, spawn_metrics_listener,
};

fn main() -> anyhow::Result<ExitCode> {
    // Parsed before Sentry and the runtime: a CLI run (`--check`, `login`, …)
    // is a short-lived tool that must not open an error stream or a log sink.
    let config_path = match cli::Cli::parse().into_action()? {
        cli::Action::Serve(path) => path,
        cli::Action::Tool(tool) => return Ok(cli::run(tool)),
    };
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
    let result = runtime.block_on(run(&config_path));

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
    result.map(|()| ExitCode::SUCCESS)
}

async fn run(config_path: &Path) -> anyhow::Result<()> {
    // Bound for the whole of `run` so the non-blocking log queue drains on
    // shutdown — see `init_logging`.
    let (_log_guard, dropped_log_lines) = init_logging()?;

    // rustls 0.23 needs an explicit CryptoProvider; install before any TLS
    // path touches `RustlsConfig` (issue #12).
    tls::install_crypto_provider();

    // Spec 05 §"resolved at config load": parse, validate (every error at
    // once), and resolve every ${ENV:…} / ${FILE:…} ref, reporting each one
    // that fails with its server/database/tier. A boot abort is a clearer
    // operator signal than the user's first query failing on connect.
    let config_file = ConfigFile::from_file(config_path)?;
    config_file.resolve_all_secrets()?;
    tracing::info!(
        path = %config_path.display(),
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
    auth_config.check_bind(config.bind)?;

    let shutdown = Shutdown::default();

    // Install the Prometheus recorder before anything starts emitting metrics.
    // `install_recorder` registers a process-wide global — tests bootstrap
    // with no recorder for that reason.
    let metrics_handle = install_recorder(shutdown.finished.clone())?;
    spawn_metrics_listener(
        config.metrics_bind,
        metrics_handle,
        shutdown.finished.clone(),
    )
    .await?;
    spawn_dropped_lines_exporter(dropped_log_lines, shutdown.finished.clone());

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
        &shutdown,
        &state_db,
    )
    .await?;

    spawn_audit_pruner(
        background_db.clone(),
        config.audit_retention_days,
        shutdown.stop.clone(),
    );
    spawn_audit_reaper(
        background_db.clone(),
        app_state.mcp.audit_sinks.clone(),
        app_state.mcp.detached.clone(),
        shutdown.stop.clone(),
    );
    startup::spawn_state_pool_sampler(
        "background",
        background_db.clone(),
        shutdown.finished.clone(),
    );
    let auth = &app_state.oauth.auth;
    spawn_auth_state_gc(
        AuthGcTargets {
            sessions: auth.sessions.clone(),
            flows: auth.flows.clone(),
            codes: auth.codes.clone(),
            refresh: auth.refresh.clone(),
            client_registry: app_state.oauth.client_registry.clone(),
        },
        shutdown.stop.clone(),
    );
    // Cloned before `serve` takes the state: the detached audit work must be
    // drained after the listener stops, and the request pool closed after that.
    let detached = app_state.mcp.detached.clone();

    let served = serve(
        &config,
        app_state,
        config_path.to_path_buf(),
        shutdown.stop.clone(),
    )
    .await;
    let pools = [("background", background_db), ("request", state_db)];
    shutdown.finish(&detached, pools).await;
    served
}

/// Insecure target TLS should not go unnoticed in a deploy log; `--check`
/// prints the same lines.
fn warn_unverified_target_tls(config_file: &ConfigFile) {
    for warning in cli::tls_warnings(config_file) {
        tracing::warn!("{warning}");
    }
}
