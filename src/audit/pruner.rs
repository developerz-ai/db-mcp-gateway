//! Retention pruner. Deletes `audit_call_intents`, `audit_calls` and
//! `permissions_audit` rows older than the configured hot-storage TTL, and
//! permissions rows revoked or soft-deleted longer ago than that (spec 07
//! §"Retention pruning"); no archive tier ships, so nothing is exported
//! first.
//!
//! Deletes run in bounded batches, each its own transaction under a
//! transaction-scoped advisory lock: a large backlog never holds one long
//! transaction or bloats the synchronous audit insert's lock queue, and two
//! replicas never delete the same batch. A replica that finds the lock taken
//! stops — the other one is pruning.
//!
//! `run_once` is the DB call tests drive directly; the background loop in
//! `startup` ticks hourly and calls it.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::state::audit::{
    RetentionTable, delete_expired_batch, referenced_expired_parents, retention_cutoff,
};

use super::AuditError;

/// Advisory-lock key for retention batches — arbitrary, fixed, distinct from
/// the reaper's.
const PRUNER_LOCK_KEY: i64 = 0x6462_6d63_7072_756e; // "dbmcprun"

/// Rows per batch: small enough that one batch commits in milliseconds.
const PRUNE_BATCH_ROWS: u32 = 5_000;

/// The floor below which retention can never drop: `ttl_days == 0` would make
/// the prune predicate `occurred_at < now()` and delete *every* audit row — a
/// silent append-only/durability violation. Retention is the floor of
/// correctness, not the ceiling, so we clamp here regardless of what the caller
/// passes. Upstream config already rejects `0`, but `run_once` is `pub` and a
/// future retention source (YAML, #16) must not be able to wipe the log.
fn effective_ttl_days(ttl: u32) -> u32 {
    ttl.max(1)
}

/// Tables in prune order. Every expired intent goes before any completion:
/// one cutoff for both keeps "intent survives ⇒ its completion survives" (a
/// completion is never older than its intent), so the reaper never sees a
/// kept intent whose completion was pruned and records a call that finished
/// as `abandoned`. Revoked grants go before the users and databases they
/// reference, so a parent's FK children are gone by the time it is reached.
const PRUNE_ORDER: [RetentionTable; 6] = [
    RetentionTable::Intents,
    RetentionTable::Calls,
    RetentionTable::PermissionsChanges,
    RetentionTable::RevokedGrants,
    RetentionTable::DeletedDatabases,
    RetentionTable::DeletedUsers,
];

/// Delete every audit row older than `ttl_days` (`occurred_at`, or `ts` for
/// `permissions_audit`) and every permissions row revoked or soft-deleted
/// before then; live permissions rows are never touched. Returns the rows removed across all tables (zero
/// when another replica holds the lock).
pub async fn run_once(pool: &PgPool, ttl_days: u32) -> Result<u64, AuditError> {
    let days = effective_ttl_days(ttl_days);
    let days = i32::try_from(days).unwrap_or(i32::MAX);
    let cutoff = retention_cutoff(pool, days)
        .await
        .map_err(AuditError::Write)?;
    prune_before(pool, cutoff).await
}

/// Delete every table's rows older than `cutoff`, in [`PRUNE_ORDER`]. A table
/// whose run yields the lock ends the whole run: another replica is pruning,
/// and expired intents may remain, so their completions must stay until a
/// run drains them.
pub async fn prune_before(pool: &PgPool, cutoff: DateTime<Utc>) -> Result<u64, AuditError> {
    let mut deleted = 0;
    for table in PRUNE_ORDER {
        let pruned = prune_table(pool, table, cutoff).await?;
        deleted += pruned.deleted;
        let Drained::Complete = pruned.drained else {
            return Ok(deleted);
        };
    }
    warn_on_referenced_parents(pool, cutoff).await?;
    Ok(deleted)
}

/// A soft-deleted parent a grant still references outlives retention; it
/// can only come from a write outside the admin API, so say so.
async fn warn_on_referenced_parents(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
) -> Result<(), AuditError> {
    let (users, databases) = referenced_expired_parents(pool, cutoff)
        .await
        .map_err(AuditError::Write)?;
    if users + databases > 0 {
        tracing::warn!(
            users,
            databases,
            "soft-deleted permissions rows past retention are still referenced by a grant; not pruned"
        );
    }
    Ok(())
}

/// Whether a table's backlog was fully deleted or the run yielded the lock.
#[derive(Debug, Clone, Copy)]
enum Drained {
    Complete,
    LockHeldElsewhere,
}

#[derive(Debug)]
struct Pruned {
    deleted: u64,
    drained: Drained,
}

/// Delete batches until one comes back short (the backlog is gone) or the
/// lock is held elsewhere.
async fn prune_table(
    pool: &PgPool,
    table: RetentionTable,
    cutoff: DateTime<Utc>,
) -> Result<Pruned, AuditError> {
    let mut deleted = 0;
    loop {
        let batch = delete_expired_batch(
            pool,
            PRUNER_LOCK_KEY,
            table,
            cutoff,
            i64::from(PRUNE_BATCH_ROWS),
        )
        .await
        .map_err(AuditError::Write)?;
        let Some(batch_deleted) = batch else {
            return Ok(Pruned {
                deleted,
                drained: Drained::LockHeldElsewhere,
            });
        };
        deleted += batch_deleted;
        if batch_deleted < u64::from(PRUNE_BATCH_ROWS) {
            return Ok(Pruned {
                deleted,
                drained: Drained::Complete,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Structural smoke: `run_once` is exposed and takes the expected shape.
    // The real-DB behaviour is covered by `tests/it_db/audit_pruner_real_db.rs`.
    #[allow(dead_code)]
    fn _signature_check(pool: &PgPool) {
        // Compiles iff the signature stays stable.
        let _fut = run_once(pool, 90);
    }

    #[test]
    fn ttl_zero_clamps_to_one_day() {
        // `0` would delete every audit row; the floor must hold.
        assert_eq!(effective_ttl_days(0), 1);
    }

    #[test]
    fn intents_are_pruned_before_their_completions() {
        assert_eq!(PRUNE_ORDER[0], RetentionTable::Intents);
        assert_eq!(PRUNE_ORDER[1], RetentionTable::Calls);
    }

    #[test]
    fn grants_are_pruned_before_the_rows_they_reference() {
        let at = |t| PRUNE_ORDER.iter().position(|&x| x == t);
        let grants = at(RetentionTable::RevokedGrants);
        assert!(grants < at(RetentionTable::DeletedDatabases));
        assert!(grants < at(RetentionTable::DeletedUsers));
    }

    #[test]
    fn ttl_passthrough_above_floor() {
        assert_eq!(effective_ttl_days(7), 7);
    }
}
