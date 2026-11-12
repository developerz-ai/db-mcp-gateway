//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.

mod sentry_scrub;
mod startup;

use std::path::PathBuf;

use clap::Parser;
use db_mcp_gateway::auth::{AuthConfig, ServiceTokenStore};
use db_mcp_gateway::config::{Config, ConfigFile};
use db_mcp_gateway::transport::tls;
use metrics_exporter_prometheus::PrometheusBuilder;

use startup::{
    build_app_state, connect_state_db, init_tracing, serve, spawn_audit_pruner,
    spawn_oauth_state_gc,
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
    // shutdown — see `init_tracing`.
    let _log_guard = init_tracing();

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

    let state_db = connect_state_db(&config).await?;
    let app_state = build_app_state(
        config_file,
        &config,
        auth_config,
        service_tokens,
        metrics_handle,
        &state_db,
    )
    .await?;

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

    serve(&config, app_state).await
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
