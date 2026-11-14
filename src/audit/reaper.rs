//! Intent reaper. An `audit_call_intents` row with no `audit_calls` row of
//! the same `request_id` means the gateway stopped (crash, OOM kill, drain
//! bound exceeded) between reaching the target and recording the outcome.
//! The reaper turns each such intent into an `outcome = "abandoned"` row so
//! the call is accounted for even though nobody saw its result.
//!
//! Runs on every replica; a transaction-scoped advisory lock lets only one
//! batch at a time.
//!
//! A sweep walks the aged intents in `(occurred_at, request_id)` order in
//! bounded batches from a [`ReapCursor`], so it never re-examines intents an
//! earlier sweep already settled and no statement grows with the retention
//! window. The cursor advances only past committed batches: a failed sweep
//! leaves it where it was and the next one retries from there, so no intent
//! is ever skipped. It lives in process memory; a restarted replica starts
//! from the oldest intent and catches up batch by batch.

use std::time::Duration;

use sqlx::PgPool;

use crate::exec::DEFAULT_STATEMENT_TIMEOUT_MS;
use crate::state::audit::{IntentKey, reap_abandoned_batch};

use super::drain::DRAIN_TIMEOUT;
use super::{AUDIT_WRITE_TIMEOUT, AuditError};

/// Advisory-lock key for the sweep — arbitrary, fixed, unique to the reaper.
const REAPER_LOCK_KEY: i64 = 0x6462_6d63_7072_6170; // "dbmcprap"

/// Calls the reaper recorded as `abandoned`: each one reached the target with
/// no recorded outcome, so an alert on any increase is warranted.
const ABANDONED_TOTAL: &str = "audit_abandoned_total";

/// Intents one batch examines: a short index range plus key probes, so a
/// batch stays far below the background pool's statement timeout.
const REAP_BATCH_ROWS: u32 = 10_000;

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

/// Where this process's next sweep resumes: the last intent a committed
/// batch examined. `Default` starts from the oldest intent.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReapCursor(Option<IntentKey>);

/// One sweep from `cursor`, batch by batch until the aged intents run out.
/// `Ok(None)` when another replica held the lock before any batch ran;
/// otherwise the number of `abandoned` rows written. `grace` is
/// [`REAPER_GRACE`] in production; tests pass zero.
pub async fn run_once(
    pool: &PgPool,
    grace: Duration,
    cursor: &mut ReapCursor,
) -> Result<Option<u64>, AuditError> {
    let mut reaped: Option<u64> = None;
    loop {
        let batch = reap_abandoned_batch(
            pool,
            REAPER_LOCK_KEY,
            grace,
            cursor.0.as_ref(),
            i64::from(REAP_BATCH_ROWS),
        )
        .await
        .map_err(AuditError::Write)?;
        let Some(batch) = batch else {
            return Ok(reaped);
        };
        reaped = Some(reaped.unwrap_or(0) + batch.reaped);
        if let Some(last) = batch.last {
            cursor.0 = Some(last);
        }
        if batch.scanned < u64::from(REAP_BATCH_ROWS) {
            return Ok(reaped);
        }
    }
}

/// Sweep every [`REAP_INTERVAL`] forever. Spawned once at boot beside the
/// retention pruner; a failed sweep is logged and retried next tick.
pub async fn run(pool: PgPool) {
    let mut ticker = tokio::time::interval(REAP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cursor = ReapCursor::default();
    loop {
        ticker.tick().await;
        match run_once(&pool, REAPER_GRACE, &mut cursor).await {
            Ok(Some(0) | None) => {}
            Ok(Some(n)) => {
                // Only the lock holder writes rows, so summing across replicas
                // counts each abandoned call once.
                metrics::counter!(ABANDONED_TOTAL).increment(n);
                tracing::warn!(rows = n, "audit reaper: recorded abandoned calls");
            }
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
