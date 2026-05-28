//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::config::ConfigFile;
use db_mcp_gateway::exec::PoolRegistry;
use db_mcp_gateway::transport::{AppState, AuthFacade, PendingFlows};
use db_mcp_gateway::{config::Config, state, transport};
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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let cli = Cli::parse();

    let config_file = ConfigFile::from_file(&cli.config)?;
    tracing::info!(
        path = %cli.config.display(),
        servers = config_file.servers.len(),
        permissions = config_file.permissions.len(),
        "config loaded"
    );

    let config = Config::from_env()?;
    let auth_config = AuthConfig::from_env()?;

    let state_db = state::connect(&config.state_db.url, config.state_db.pool_size).await?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "state DB connected, migrations applied"
    );

    let sessions = SessionStore::new(state_db.clone());
    let oidc = OidcClient::new(auth_config.clone())?;
    let app_state = AppState {
        auth: Some(AuthFacade {
            config: Arc::new(auth_config),
            sessions,
            oidc,
            flows: PendingFlows::default(),
        }),
        config: Arc::new(config_file),
        pool_registry: PoolRegistry::new(),
        state_db: Some(state_db),
    };

    let app = transport::router(&config, app_state);

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let addr = listener.local_addr()?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        %addr,
        path = %config.mcp_path,
        "db-mcp-gateway listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

/// Resolve when the process receives Ctrl-C or (on Unix) SIGTERM, so containers
/// drain cleanly on `docker stop`.
async fn shutdown_signal() {
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
