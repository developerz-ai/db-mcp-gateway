//! Retention pruner. Deletes `audit_calls` rows older than the configured
//! hot-storage TTL.
//!
//! Spec 07 §"Retention pruning": a background task runs hourly, archives
//! aged rows if an archive sink is configured, then deletes from hot. For
//! #8 we ship only the delete — the archive tier (S3/GCS/Azure) lands in a
//! follow-up.
//!
//! `run_once` is the pure DB call so tests can drive it directly; the
//! production loop in `main.rs` ticks `tokio::time::interval` and calls it.

use sqlx::PgPool;

use super::AuditError;

/// Delete every row whose `occurred_at` is older than `ttl_days`. Returns
/// the number of rows removed.
pub async fn run_once(pool: &PgPool, ttl_days: u32) -> Result<u64, AuditError> {
    // `interval '1 day' * $1` keeps the SQL portable to older Postgres
    // versions (`make_interval` is 14+). The cast on the bind is needed so
    // sqlx infers the parameter type — Postgres won't let `int * interval`
    // happen with a freshly-bound untyped param.
    let result = sqlx::query(
        "DELETE FROM audit_calls \
         WHERE occurred_at < now() - (interval '1 day' * $1::int)",
    )
    .bind(i32::try_from(ttl_days).unwrap_or(i32::MAX))
    .execute(pool)
    .await
    .map_err(AuditError::Write)?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Structural smoke: `run_once` is exposed and takes the expected shape.
    // The real-DB behaviour is covered by `tests/audit_pruner_real_db.rs`.
    #[allow(dead_code)]
    fn _signature_check(pool: &PgPool) {
        // Compiles iff the signature stays stable.
        let _fut = run_once(pool, 90);
    }
}
