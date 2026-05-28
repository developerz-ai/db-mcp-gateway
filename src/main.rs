//! db-mcp-gateway — entry point: logging, config, signals, graceful shutdown.

use std::sync::Arc;

use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore};
use db_mcp_gateway::transport::{AppState, AuthFacade, PendingFlows};
use db_mcp_gateway::{config::Config, state, transport};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Config::from_env()?;
    let auth_config = AuthConfig::from_env()?;

    let state_db = state::connect(&config.state_db.url, config.state_db.pool_size).await?;
    tracing::info!(
        pool_size = config.state_db.pool_size,
        "state DB connected, migrations applied"
    );

    let sessions = SessionStore::new(state_db);
    let oidc = OidcClient::new(auth_config.clone())?;
    let app_state = AppState {
        auth: Some(AuthFacade {
            config: Arc::new(auth_config),
            sessions,
            oidc,
            flows: PendingFlows::default(),
        }),
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

    axum::serve(listener, app)
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
