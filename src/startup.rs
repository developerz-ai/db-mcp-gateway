use sqlx::PgPool;

use db_mcp_gateway::audit;
use db_mcp_gateway::transport::probes::ShutdownFlag;
use db_mcp_gateway::transport::tls;
use db_mcp_gateway::transport::{AuthCodes, PendingFlows, RefreshTokens};

/// Background task: tick hourly and prune any audit row older than the
/// configured TTL. The task is detached — `tokio::time::interval` survives
/// missed ticks (DelayBehavior) and the runtime cancels it on graceful
/// shutdown, which is safe because the only DB write is a single DELETE.
pub(crate) fn spawn_audit_pruner(pool: PgPool, ttl_days: u32) {
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

/// Background task: tick every 30 seconds and remove expired OAuth state
/// (authorization codes, pending flows, refresh tokens). The task is
/// detached — cancellation on graceful shutdown is safe because it's pure
/// memory-local operations (no I/O).
pub(crate) fn spawn_oauth_state_gc(flows: PendingFlows, codes: AuthCodes, refresh: RefreshTokens) {
    use std::time::Duration;
    use tokio::time::{MissedTickBehavior, interval};

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            flows.gc_expired().await;
            codes.gc_expired().await;
            refresh.gc_expired().await;
            tracing::debug!("oauth state gc completed");
        }
    });
}

/// Install the shutdown signal handlers and return a future that resolves on
/// the first Ctrl-C or (on Unix) SIGTERM, so containers drain cleanly on
/// `docker stop`. The awaited future flips `shutdown` *before* axum starts
/// draining, so `/healthz` and `/readyz` go 503 in time for k8s to pull the
/// pod out of the Service endpoint set.
///
/// The SIGTERM handler is registered **synchronously** here so a registration
/// failure surfaces as an `Err` the caller bubbles to `main`, failing boot —
/// serving on while `docker stop` can't drain is a silent violation of the
/// runtime contract (`docs/deployment/quickstart.md`). `tokio::signal::ctrl_c`
/// exposes no separate install step, so its (rare) failure can only be caught
/// when the future is polled; there we log and stall that arm so `select!`
/// still waits for a real signal rather than shutting down spuriously.
pub(crate) fn install_shutdown_signal(
    shutdown: ShutdownFlag,
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

        shutdown.trigger();
        tracing::info!("shutdown signal received");
    })
}

/// Install the SIGHUP handler and spawn the cert hot-reload loop: on every
/// signal, re-read cert+key from the configured paths and hand them to the
/// running `RustlsConfig`. Reload failure (bad file mid-swap) is logged loudly
/// but never crashes the gateway — the old cert keeps serving until the next
/// signal succeeds.
///
/// The handler is registered **synchronously** so a registration failure
/// bubbles to `main` and fails boot, rather than serving on with a dead
/// `kill -HUP` TLS reload path (`docs/deployment/quickstart.md`). The loop
/// itself runs in a detached task because `signal(SIGHUP)` is a long-lived
/// stream; the runtime cancels it on shutdown.
#[cfg(unix)]
pub(crate) fn spawn_reload_on_sighup(
    rustls: axum_server::tls_rustls::RustlsConfig,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
) -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
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
    });
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn spawn_reload_on_sighup(
    _rustls: axum_server::tls_rustls::RustlsConfig,
    _cert_path: std::path::PathBuf,
    _key_path: std::path::PathBuf,
) -> std::io::Result<()> {
    // SIGHUP doesn't exist outside Unix; deployment targets are Linux only.
    Ok(())
}
