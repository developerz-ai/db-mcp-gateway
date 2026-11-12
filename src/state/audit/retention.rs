//! Retention deletes for `audit_calls` and `audit_call_intents`: one bounded
//! batch per call, each in its own transaction under a transaction-scoped
//! advisory lock, so replicas never delete the same rows at once and a
//! dropped connection can never strand the lock on a pooled session.

use sqlx::PgPool;

/// Which append-only audit table a batch prunes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditTable {
    Calls,
    Intents,
}

impl AuditTable {
    // `ORDER BY occurred_at LIMIT` walks `*_occurred_at_idx`, oldest first,
    // so each batch is an index range plus key lookups, never a full scan.
    fn delete_batch_sql(self) -> &'static str {
        match self {
            Self::Calls => {
                "DELETE FROM audit_calls WHERE id IN ( \
                   SELECT id FROM audit_calls \
                   WHERE occurred_at < now() - (interval '1 day' * $1::int) \
                   ORDER BY occurred_at LIMIT $2)"
            }
            Self::Intents => {
                "DELETE FROM audit_call_intents WHERE request_id IN ( \
                   SELECT request_id FROM audit_call_intents \
                   WHERE occurred_at < now() - (interval '1 day' * $1::int) \
                   ORDER BY occurred_at LIMIT $2)"
            }
        }
    }
}

/// Delete up to `limit` rows of `table` older than `days`, oldest first.
/// `Ok(None)` when another replica holds `lock_key`; otherwise the count.
pub async fn delete_expired_batch(
    pool: &PgPool,
    lock_key: i64,
    table: AuditTable,
    days: i32,
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
        .bind(days)
        .bind(limit)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(Some(deleted))
}
