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

/// Resolve when the process receives Ctrl-C or (on Unix) SIGTERM, so containers
/// drain cleanly on `docker stop`. Flips `shutdown` *before* axum starts
/// draining, so `/healthz` and `/readyz` go 503 in time for k8s to pull the
/// pod out of the Service endpoint set.
pub(crate) async fn shutdown_signal(shutdown: ShutdownFlag) {
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

/// SIGHUP loop: every signal, re-read cert+key from the configured paths and
/// hand them to the running `RustlsConfig`. Reload failure is logged loudly
/// but never crashes the gateway — the old cert keeps serving until the next
/// signal succeeds. Runs in its own task because `tokio::signal::unix::signal`
/// is a long-lived stream.
#[cfg(unix)]
pub(crate) async fn reload_on_sighup(
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
pub(crate) async fn reload_on_sighup(
    _rustls: axum_server::tls_rustls::RustlsConfig,
    _cert_path: std::path::PathBuf,
    _key_path: std::path::PathBuf,
) {
    // SIGHUP doesn't exist outside Unix; deployment targets are Linux only.
    std::future::pending::<()>().await;
}
