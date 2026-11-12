//! Bind the listener (TLS or dev-only plain HTTP) and serve until a shutdown
//! signal drains it.

use db_mcp_gateway::config::{Config, TlsConfig};
use db_mcp_gateway::transport::{self, AppState, tls};

use super::{install_shutdown_signal, spawn_reload_on_sighup};

pub(crate) async fn serve(config: &Config, app_state: AppState) -> anyhow::Result<()> {
    let shutdown_for_signal = app_state.shutdown.clone();
    let app = transport::router(config, app_state)?;

    let handle = axum_server::Handle::new();
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
