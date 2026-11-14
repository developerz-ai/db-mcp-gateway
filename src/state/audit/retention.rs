//! Retention deletes for the audit tables (`audit_calls`,
//! `audit_call_intents`, `permissions_audit`) and for dead permissions rows
//! (revoked grants, soft-deleted users and databases): one bounded batch per
//! call, each in its own transaction under a transaction-scoped advisory
//! lock, so replicas never delete the same rows at once and a dropped
//! connection can never strand the lock on a pooled session.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// Which table a retention batch prunes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionTable {
    Calls,
    Intents,
    /// The admin API's change trail; timestamped by `ts`, not `occurred_at`.
    PermissionsChanges,
    /// `permissions_grants` rows revoked before the cutoff.
    RevokedGrants,
    /// `permissions_databases` rows soft-deleted before the cutoff that no
    /// grant references any more.
    DeletedDatabases,
    /// `permissions_users` rows soft-deleted before the cutoff that no grant
    /// references any more.
    DeletedUsers,
}

impl RetentionTable {
    // `ORDER BY <timestamp> LIMIT` walks the table's timestamp index
    // (`*_occurred_at_idx`, `permissions_audit_ts_idx`, the 0020 dead-row
    // indexes), oldest first, so each batch is an index range plus key
    // lookups, never a full scan. A parent still referenced by any grant is
    // skipped rather than deleted: the FK would refuse it, and such a row is
    // an anomaly `referenced_expired_parents` reports.
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
            Self::RevokedGrants => {
                "DELETE FROM permissions_grants WHERE id IN ( \
                   SELECT id FROM permissions_grants \
                   WHERE revoked_at < $1 \
                   ORDER BY revoked_at LIMIT $2)"
            }
            Self::DeletedDatabases => {
                "DELETE FROM permissions_databases WHERE id IN ( \
                   SELECT d.id FROM permissions_databases d \
                   WHERE d.deleted_at < $1 \
                     AND NOT EXISTS ( \
                       SELECT 1 FROM permissions_grants g WHERE g.database_id = d.id) \
                   ORDER BY d.deleted_at LIMIT $2)"
            }
            Self::DeletedUsers => {
                "DELETE FROM permissions_users WHERE id IN ( \
                   SELECT u.id FROM permissions_users u \
                   WHERE u.deleted_at < $1 \
                     AND NOT EXISTS ( \
                       SELECT 1 FROM permissions_grants g WHERE g.user_id = u.id) \
                   ORDER BY u.deleted_at LIMIT $2)"
            }
        }
    }
}

/// Soft-deleted users and databases past `cutoff` that a grant still
/// references, so retention cannot delete them. The admin API revokes a
/// parent's grants in the transaction that soft-deletes it, so after the
/// grants are pruned this should be `(0, 0)`; anything else is a row written
/// outside the admin API.
pub async fn referenced_expired_parents(
    pool: &PgPool,
    cutoff: DateTime<Utc>,
) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM permissions_users u WHERE u.deleted_at < $1 \
              AND EXISTS (SELECT 1 FROM permissions_grants g WHERE g.user_id = u.id)), \
           (SELECT count(*) FROM permissions_databases d WHERE d.deleted_at < $1 \
              AND EXISTS (SELECT 1 FROM permissions_grants g WHERE g.database_id = d.id))",
    )
    .bind(cutoff)
    .fetch_one(pool)
    .await
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
    table: RetentionTable,
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
