//! Supervised background loops: the audit pruner and the auth state GC.
//!
//! Each loop stops when the shutdown token fires and is restarted if it
//! panics — a panicking prune must not end retention for the life of the pod.
//! First ticks are jittered so replicas restarted together do not prune in
//! lockstep, and so a crash-looping pod does not prune on every boot.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::PgPool;
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

use db_mcp_gateway::audit;
use db_mcp_gateway::auth::SessionStore;
use db_mcp_gateway::auth::oauth::{AuthCodes, ClientRegistry, PendingFlows, RefreshTokens};

const PRUNE_EVERY: Duration = Duration::from_secs(3600);
const PRUNE_MAX_JITTER: Duration = Duration::from_secs(300);
/// Expired auth state is harmless until collected — lookups check expiry —
/// so minutes, not seconds: at 30 s this loop was most of D1's log volume and
/// a seq-scan DELETE every tick (plan 101 slice 01 findings 3–4).
const AUTH_GC_EVERY: Duration = Duration::from_secs(300);
const RESTART_BACKOFF: Duration = Duration::from_secs(5);

/// Run `make_loop()` until `shutdown`; restart it after a panic.
pub(crate) fn supervise<F, Fut>(name: &'static str, shutdown: CancellationToken, make_loop: F)
where
    F: Fn(CancellationToken) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let run = tokio::spawn(make_loop(shutdown.clone()));
            match run.await {
                Ok(()) => return,
                Err(err) if err.is_panic() => {
                    tracing::error!(task = name, "background task panicked; restarting");
                }
                Err(_) => return,
            }
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(RESTART_BACKOFF) => {}
            }
        }
    });
}

/// Hourly audit retention prune on the background pool.
pub(crate) fn spawn_audit_pruner(pool: PgPool, ttl_days: u32, shutdown: CancellationToken) {
    supervise("audit_pruner", shutdown, move |shutdown| {
        let pool = pool.clone();
        async move {
            let start = Instant::now() + jitter(PRUNE_MAX_JITTER);
            let mut ticker = interval_at(start, PRUNE_EVERY);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = ticker.tick() => prune_once(&pool, ttl_days).await,
                }
            }
        }
    });
}

/// Two-phase audit reaper (`audit::reaper::run`) on the background pool:
/// intent rows with no completion become `abandoned`.
pub(crate) fn spawn_audit_reaper(pool: PgPool, shutdown: CancellationToken) {
    supervise("audit_reaper", shutdown, move |shutdown| {
        let pool = pool.clone();
        async move {
            tokio::select! {
                _ = shutdown.cancelled() => {}
                _ = audit::reaper::run(pool) => {}
            }
        }
    });
}

async fn prune_once(pool: &PgPool, ttl_days: u32) {
    match audit::pruner::run_once(pool, ttl_days).await {
        Ok(rows) => {
            metrics::counter!("audit_pruner_runs_total", "result" => "ok").increment(1);
            metrics::gauge!("audit_pruner_last_success_timestamp").set(unix_now_secs());
            if rows > 0 {
                tracing::info!(rows, ttl_days, "pruned old audit rows");
            }
        }
        Err(err) => {
            metrics::counter!("audit_pruner_runs_total", "result" => "error").increment(1);
            tracing::error!(%err, "audit pruner run failed");
        }
    }
}

/// The auth stores the GC loop sweeps.
pub(crate) struct AuthGcTargets {
    pub(crate) sessions: SessionStore,
    pub(crate) flows: PendingFlows,
    pub(crate) codes: AuthCodes,
    pub(crate) refresh: RefreshTokens,
    pub(crate) client_registry: ClientRegistry,
}

/// Collect expired sessions, authorization codes, pending flows, refresh
/// tokens and dynamic client registrations (state-DB I/O). Logs only when it
/// deleted something; the stores log their own DB failures.
pub(crate) fn spawn_auth_state_gc(targets: AuthGcTargets, shutdown: CancellationToken) {
    let targets = std::sync::Arc::new(targets);
    supervise("auth_state_gc", shutdown, move |shutdown| {
        let targets = targets.clone();
        async move {
            let start = Instant::now() + AUTH_GC_EVERY + jitter(AUTH_GC_EVERY);
            let mut ticker = interval_at(start, AUTH_GC_EVERY);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    _ = ticker.tick() => gc_once(&targets).await,
                }
            }
        }
    });
}

async fn gc_once(targets: &AuthGcTargets) {
    let flows = targets.flows.gc_expired().await;
    let codes = targets.codes.gc_expired().await;
    let refresh_tokens = targets.refresh.gc_expired().await;
    let clients = targets.client_registry.gc_expired().await;
    let sessions = match targets.sessions.gc_expired().await {
        Ok(rows) => rows,
        Err(error) => {
            // `AuthError` Display is static ("session state DB error"), no DSN.
            tracing::warn!(%error, "session GC failed");
            0
        }
    };
    if flows + codes + refresh_tokens + clients + sessions > 0 {
        tracing::info!(
            flows,
            codes,
            refresh_tokens,
            clients,
            sessions,
            "deleted expired auth state"
        );
    }
}

/// A cheap, non-cryptographic offset in `[0, max)`: spreading first ticks
/// across replicas needs no RNG, only different values per process.
fn jitter(max: Duration) -> Duration {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default()
        ^ std::process::id();
    let max_ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX).max(1);
    Duration::from_millis(u64::from(seed) % max_ms)
}

fn unix_now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn jitter_stays_below_its_bound() {
        for _ in 0..100 {
            assert!(jitter(Duration::from_secs(3)) < Duration::from_secs(3));
        }
    }

    /// Real time: the restart waits out `RESTART_BACKOFF` (~5 s).
    #[tokio::test]
    async fn supervisor_restarts_a_panicked_loop_and_stops_on_shutdown() {
        let runs = Arc::new(AtomicUsize::new(0));
        let shutdown = CancellationToken::new();
        let counted = runs.clone();
        supervise("test", shutdown.clone(), move |shutdown| {
            let run = counted.fetch_add(1, Ordering::SeqCst);
            async move {
                assert!(run > 0, "first run panics");
                shutdown.cancelled().await;
            }
        });

        let deadline = Instant::now() + RESTART_BACKOFF * 4;
        while runs.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "loop was not restarted");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        shutdown.cancel();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "restarted after shutdown");
    }
}
