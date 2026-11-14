//! Retention deletes for `audit_calls`, `audit_call_intents` and
//! `permissions_audit`: one bounded
//! batch per call, each in its own transaction under a transaction-scoped
//! advisory lock, so replicas never delete the same rows at once and a
//! dropped connection can never strand the lock on a pooled session.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Which append-only audit table a batch prunes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditTable {
    Calls,
    Intents,
    /// The admin API's change trail; timestamped by `ts`, not `occurred_at`.
    PermissionsChanges,
}

impl AuditTable {
    // `ORDER BY <timestamp> LIMIT` walks the table's timestamp index
    // (`*_occurred_at_idx`, `permissions_audit_ts_idx`), oldest first, so each
    // batch is an index range plus key lookups, never a full scan.
    fn delete_batch_sql(self) -> &'static str {
        match self {
            Self::Calls => {
                "DELETE FROM audit_calls WHERE id IN ( \
                   SELECT id FROM audit_calls \
                   WHERE occurred_at < $1 \
                   ORDER BY occurred_at LIMIT $2)"
            }
            Self::Intents => {
                "DELETE FROM audit_call_intents WHERE request_id IN ( \
                   SELECT request_id FROM audit_call_intents \
                   WHERE occurred_at < $1 \
                   ORDER BY occurred_at LIMIT $2)"
            }
            Self::PermissionsChanges => {
                "DELETE FROM permissions_audit WHERE id IN ( \
                   SELECT id FROM permissions_audit \
                   WHERE ts < $1 \
                   ORDER BY ts LIMIT $2)"
            }
        }
    }
}

/// The retention cutoff `days` before the state DB's clock. Computed once
/// per prune run so every batch of every table deletes against the same
/// instant.
pub async fn retention_cutoff(pool: &PgPool, days: i32) -> Result<DateTime<Utc>, sqlx::Error> {
    sqlx::query_scalar("SELECT now() - make_interval(days => $1)")
        .bind(days)
        .fetch_one(pool)
        .await
}

/// Delete up to `limit` rows of `table` older than `cutoff`, oldest first.
/// `Ok(None)` when another replica holds `lock_key`; otherwise the count.
pub async fn delete_expired_batch(
    pool: &PgPool,
    lock_key: i64,
    table: AuditTable,
    cutoff: DateTime<Utc>,
    limit: i64,
) -> Result<Option<u64>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(lock_key)
        .fetch_one(&mut *tx)
        .await?;
    if !locked {
        tx.rollback().await?;
        return Ok(None);
    }
    let deleted = sqlx::query(table.delete_batch_sql())
        .bind(cutoff)
        .bind(limit)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(Some(deleted))
}
