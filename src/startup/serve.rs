//! Bind the listener (TLS or dev-only plain HTTP) and serve until a shutdown
//! signal drains it.

use std::path::PathBuf;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use db_mcp_gateway::config::reload::ReloadTargets;
use db_mcp_gateway::config::{Config, TlsConfig};
use db_mcp_gateway::transport::{self, AppState, tls};

use super::{install_shutdown_signal, spawn_reload_on_sighup};

/// Headroom past the request ceiling so a request that runs right up to the
/// router timeout still gets its response out before the connection is cut.
const DRAIN_MARGIN: Duration = Duration::from_secs(5);

/// How long in-flight requests get after SIGTERM: the `/mcp` request timeout
/// (the slowest legitimate request) plus margin. A shorter window cuts a slow call mid-flight and
/// loses its completion audit row. The pod's `terminationGracePeriodSeconds`
/// must exceed this plus the detached-audit drain and the pool closes
/// (website/docs/deployment).
pub(crate) const DRAIN_WINDOW: Duration =
    Duration::from_secs(transport::MCP_TIMEOUT.as_secs() + DRAIN_MARGIN.as_secs());

pub(crate) async fn serve(
    config: &Config,
    app_state: AppState,
    config_path: PathBuf,
    stop: CancellationToken,
) -> anyhow::Result<()> {
    let reload = ReloadTargets {
        path: config_path,
        config: app_state.mcp.config.clone(),
        audit_sinks: app_state.mcp.audit_sinks.clone(),
        service_tokens: app_state.oauth.auth.service_tokens.clone(),
        permissions_cache: app_state.mcp.permissions_cache.clone(),
        adapter_registry: app_state.mcp.adapter_registry.clone(),
    };
    let app = transport::router(config, app_state)?;

    let handle = axum_server::Handle::new();
    let handle_for_signal = handle.clone();
    // Install signal handlers synchronously so a registration failure aborts
    // boot instead of leaving the server unable to drain on `docker stop`.
    let signal_fut = install_shutdown_signal(stop.clone())?;
    tokio::spawn(async move {
        signal_fut.await;
        handle_for_signal.graceful_shutdown(Some(DRAIN_WINDOW));
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
            spawn_reload_on_sighup(config.tls.clone(), Some(rustls.clone()), reload, stop)?;
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
            spawn_reload_on_sighup(TlsConfig::Disabled, None, reload, stop)?;
            axum_server::bind(config.bind)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use db_mcp_gateway::transport::MCP_TIMEOUT;

    use super::DRAIN_WINDOW;

    /// The drain must outlast the slowest `/mcp` request or SIGTERM loses its
    /// outcome audit row.
    #[test]
    fn drain_window_outlasts_the_mcp_request_timeout() {
        assert!(
            DRAIN_WINDOW > MCP_TIMEOUT,
            "{DRAIN_WINDOW:?} <= {MCP_TIMEOUT:?}"
        );
    }
}
