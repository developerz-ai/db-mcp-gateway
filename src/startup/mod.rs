//! Boot wiring, signals, and the background work the server runs alongside.

use tokio_util::sync::CancellationToken;

use db_mcp_gateway::config::reload::ReloadTargets;
use db_mcp_gateway::config::{self, TlsConfig};
use db_mcp_gateway::transport::tls;

mod background;
mod boot;
mod logging;
mod metrics;
mod serve;

pub(crate) use background::{
    AuthGcTargets, spawn_audit_pruner, spawn_audit_reaper, spawn_auth_state_gc,
};
pub(crate) use boot::{build_app_state, connect_state_db};
pub(crate) use logging::{init_logging, spawn_dropped_lines_exporter};
pub(crate) use metrics::{install_recorder, spawn_listener as spawn_metrics_listener};
pub(crate) use serve::serve;

/// Install the shutdown signal handlers and return a future that resolves on
/// the first Ctrl-C or (on Unix) SIGTERM, so containers drain cleanly on
/// `docker stop`. The awaited future cancels `stop` — the token `AppState`
/// carries as `shutdown` — *before* axum starts draining, so `/healthz` and
/// `/readyz` go 503 in time for k8s to pull the pod out of the Service
/// endpoint set, and background loops and the metrics listener wind down.
///
/// The SIGTERM handler is registered **synchronously** here so a registration
/// failure surfaces as an `Err` the caller bubbles to `main`, failing boot —
/// serving on while `docker stop` can't drain is a silent violation of the
/// runtime contract (`docs/deployment/quickstart.md`). `tokio::signal::ctrl_c`
/// exposes no separate install step, so its (rare) failure can only be caught
/// when the future is polled; there we log and stall that arm so `select!`
/// still waits for a real signal rather than shutting down spuriously.
pub(crate) fn install_shutdown_signal(
    stop: CancellationToken,
) -> std::io::Result<impl std::future::Future<Output = ()>> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    Ok(async move {
        let ctrl_c = async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "failed to install Ctrl-C handler");
                std::future::pending::<()>().await;
            }
        };

        #[cfg(unix)]
        let terminate = async {
            terminate.recv().await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        stop.cancel();
        tracing::info!("shutdown signal received");
    })
}

/// Install the SIGHUP handler and spawn the reload loop: on every signal,
/// re-read cert+key (when TLS is on) into the running `RustlsConfig`, then
/// reload the YAML config ([`config::reload::reload`]). Either failure is
/// logged loudly but never crashes the gateway — the previous cert and config
/// keep serving until the next signal succeeds.
///
/// Installed whether or not TLS is on: SIGHUP's default disposition
/// terminates the process, so with TLS off an operator's `kill -HUP` (the
/// documented reload signal) used to kill the gateway.
///
/// The handler is registered **synchronously** so a registration failure
/// bubbles to `main` and fails boot. The loop runs in a detached task until
/// `stop` fires.
#[cfg(unix)]
pub(crate) fn spawn_reload_on_sighup(
    tls_config: TlsConfig,
    rustls: Option<axum_server::tls_rustls::RustlsConfig>,
    reload: ReloadTargets,
    stop: CancellationToken,
) -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                received = hup.recv() => {
                    if received.is_none() {
                        return;
                    }
                    tracing::info!("SIGHUP received");
                    if let (TlsConfig::Enabled { cert_path, key_path }, Some(rustls)) =
                        (&tls_config, rustls.as_ref())
                    {
                        reload_tls(rustls, cert_path, key_path).await;
                    }
                    reload_config(&reload).await;
                }
            }
        }
    });
    Ok(())
}

#[cfg(unix)]
async fn reload_tls(
    rustls: &axum_server::tls_rustls::RustlsConfig,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) {
    match tls::reload(rustls, cert_path, key_path).await {
        Ok(()) => tracing::info!(cert_path = %cert_path.display(), "TLS certificate reloaded"),
        Err(error) => tracing::error!(
            %error,
            cert_path = %cert_path.display(),
            "TLS certificate reload failed; keeping previous cert"
        ),
    }
}

async fn reload_config(targets: &ReloadTargets) {
    match config::reload::reload(targets).await {
        Ok(evicted) => tracing::info!(
            path = %targets.path.display(),
            evicted_pools = evicted,
            "config reloaded"
        ),
        // `ReloadError` names files, env vars and settings — never a secret.
        Err(error) => tracing::error!(
            %error,
            path = %targets.path.display(),
            "config reload failed; keeping previous config"
        ),
    }
}

#[cfg(not(unix))]
pub(crate) fn spawn_reload_on_sighup(
    _tls_config: TlsConfig,
    _rustls: Option<axum_server::tls_rustls::RustlsConfig>,
    _reload: ReloadTargets,
    _stop: CancellationToken,
) -> std::io::Result<()> {
    // SIGHUP doesn't exist outside Unix; deployment targets are Linux only.
    Ok(())
}

#[cfg(all(test, unix))]
mod sighup_tests;
