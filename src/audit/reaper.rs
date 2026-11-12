//! Intent reaper. An `audit_call_intents` row with no `audit_calls` row of
//! the same `request_id` means the gateway stopped (crash, OOM kill, drain
//! bound exceeded) between reaching the target and recording the outcome.
//! The reaper turns each such intent into an `outcome = "abandoned"` row so
//! the call is accounted for even though nobody saw its result.
//!
//! Runs on every replica; a transaction-scoped advisory lock lets only one
//! sweep at a time.

use std::time::Duration;

use sqlx::PgPool;

use crate::exec::DEFAULT_STATEMENT_TIMEOUT_MS;

use super::drain::DRAIN_TIMEOUT;
use super::{AUDIT_WRITE_TIMEOUT, AuditError};

/// Advisory-lock key for the sweep — arbitrary, fixed, unique to the reaper.
const REAPER_LOCK_KEY: i64 = 0x6462_6d63_7072_6170; // "dbmcprap"

/// How often a replica attempts a sweep.
pub const REAP_INTERVAL: Duration = Duration::from_secs(60);

/// Opening the target pool and acquiring a connection happen after the intent
/// is written and are not bounded by the statement ceiling.
const TARGET_OPEN_ALLOWANCE: Duration = Duration::from_secs(60);

/// An intent younger than this may belong to a call that is still running:
/// the longest a live dispatch can take from intent to completion row is the
/// target open, the statement ceiling, the completion write and its fallback
/// retry, and a shutdown drain. Reaping earlier would write `abandoned` for a
/// call that then also records its real outcome.
pub const REAPER_GRACE: Duration = Duration::from_secs(
    TARGET_OPEN_ALLOWANCE.as_secs()
        + DEFAULT_STATEMENT_TIMEOUT_MS as u64 / 1000
        + 2 * AUDIT_WRITE_TIMEOUT.as_secs()
        + DRAIN_TIMEOUT.as_secs(),
);

/// One sweep. `Ok(None)` when another replica holds the lock; otherwise the
/// number of `abandoned` rows written. `grace` is [`REAPER_GRACE`] in
/// production; tests pass zero.
pub async fn run_once(pool: &PgPool, grace: Duration) -> Result<Option<u64>, AuditError> {
    crate::state::audit::reap_abandoned_intents(pool, REAPER_LOCK_KEY, grace)
        .await
        .map_err(AuditError::Write)
}

/// Sweep every [`REAP_INTERVAL`] forever. Spawned once at boot beside the
/// retention pruner; a failed sweep is logged and retried next tick.
pub async fn run(pool: PgPool) {
    let mut ticker = tokio::time::interval(REAP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match run_once(&pool, REAPER_GRACE).await {
            Ok(Some(0) | None) => {}
            Ok(Some(n)) => tracing::warn!(rows = n, "audit reaper: recorded abandoned calls"),
            Err(err) => tracing::error!(
                %err,
                class = %err.class(),
                "audit reaper sweep failed"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_covers_every_bound_a_live_dispatch_can_hit() {
        assert!(REAPER_GRACE > DRAIN_TIMEOUT + AUDIT_WRITE_TIMEOUT * 2);
        assert!(REAPER_GRACE.as_millis() > u128::from(DEFAULT_STATEMENT_TIMEOUT_MS));
    }
}
