//! The baseline path: the same SQL, straight at Postgres over sqlx.
//!
//! This is what the gateway is measured *against*, so it must be as fast as a
//! well-written application would be — a slow baseline flatters the gateway.
//! Hence a warm pool sized to the driver's concurrency, and no per-request
//! connect. Anything that makes this path artificially slow makes the
//! published overhead artificially small, which is the failure mode this whole
//! exercise exists to avoid.
//!
//! The pool-sizing and empty-result discipline is shared with the mongo
//! baseline ([`crate::mongo`]): both must size their pool to the concurrency
//! so no request queues for a connection, and both must reject an empty
//! result rather than time it. Those two rules live in [`pool_size_for`] and
//! [`ensure_non_empty`] so the two baselines cannot drift apart.

use std::time::Instant;

use sqlx::{Row, postgres::PgPoolOptions};

use crate::workload::Shape;

#[derive(Debug, thiserror::Error)]
pub enum DirectError {
    // Stable bracketed prefix so a report consumer (or a `grep` over the
    // harness log) can classify failures without pattern-matching the
    // downstream SQLx prose, which changes between driver versions.
    #[error("[BENCH_DIRECT_DB] direct database access failed: {0}")]
    Db(#[from] sqlx::Error),
    /// The query succeeded but returned nothing. `RowNotFound` would render as
    /// a database failure, which points an operator at connectivity instead of
    /// at the query shape — and a benchmark measuring an empty result set is
    /// measuring a no-op.
    #[error("[BENCH_DIRECT_EMPTY_RESULT] shape {shape} returned no rows at iteration {iteration}")]
    EmptyResult { shape: &'static str, iteration: u64 },
}

/// Pool size for a baseline path serving `concurrency` concurrent requests.
///
/// One connection per in-flight request, never fewer. A pool smaller than the
/// concurrency would queue requests, and that queueing would be measured as
/// latency and charged, wrongly, to the database — flattering the gateway.
/// Never zero: at least one connection, so a `concurrency: 0` still works.
pub fn pool_size_for(concurrency: u32) -> u32 {
    concurrency.max(1)
}

/// Reject an empty result set.
///
/// Shared with the mongo baseline: timing a query that returned nothing is
/// how a benchmark publishes an impossibly good number. The caller supplies
/// what it observed; this turns "nothing came back" into an error.
///
/// `observed` is the number of rows/documents the driver reported.
pub fn ensure_non_empty(
    observed: usize,
    shape: &'static str,
    iteration: u64,
) -> Result<(), DirectError> {
    if observed == 0 {
        return Err(DirectError::EmptyResult { shape, iteration });
    }
    Ok(())
}

/// A pooled direct-to-Postgres client.
#[derive(Debug, Clone)]
pub struct DirectClient {
    pool: sqlx::PgPool,
}

impl DirectClient {
    /// `concurrency` sizes the pool so no request ever waits for a connection.
    /// Queueing here would be measured as latency and charged, wrongly, to the
    /// database.
    pub async fn connect(url: &str, concurrency: u32) -> Result<Self, DirectError> {
        let size = pool_size_for(concurrency);
        let pool = PgPoolOptions::new()
            .max_connections(size)
            .min_connections(size)
            .connect(url)
            .await?;
        Ok(DirectClient { pool })
    }

    /// Run `ddl` — the seed or cleanup script for the backend being
    /// measured ([`crate::workload::postgres_seed`],
    /// [`crate::workload::postgres_write_seed`] or
    /// [`crate::workload::postgres_write_cleanup`]).
    ///
    /// **Destructive.** The seeds open with `DROP TABLE IF EXISTS`, so any
    /// existing table of that name in the target database is discarded. Point
    /// the harness at a disposable database only. The drop is what makes a
    /// re-run measure the same bytes rather than appending to the previous
    /// run's data.
    pub async fn execute_ddl(&self, ddl: &str) -> Result<(), DirectError> {
        // `execute` on a multi-statement string runs it as one implicit
        // transaction, which is what we want: a half-seeded table would make
        // every subsequent number meaningless.
        sqlx::raw_sql(ddl).execute(&self.pool).await?;
        Ok(())
    }

    /// Issue one query and return its wall-clock latency in milliseconds.
    ///
    /// Rows are fully drained and their columns touched before the clock
    /// stops. sqlx would otherwise let us stop timing while the server is
    /// still streaming, making the baseline look faster than any real client
    /// could be — and inflating the gateway's apparent overhead.
    pub async fn run(&self, shape: Shape, iteration: u64) -> Result<f64, DirectError> {
        let sql = shape.sql(iteration);

        let started = Instant::now();
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        let mut touched = 0usize;
        for row in &rows {
            touched += row.columns().len();
        }
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;

        // Keep the drain from being optimised into nothing, and catch a
        // silently-empty result set — the same no-op trap guarded on the
        // gateway side.
        debug_assert!(touched > 0 || rows.is_empty());
        ensure_non_empty(rows.len(), shape.name(), iteration)?;

        Ok(elapsed)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pool_is_never_smaller_than_the_concurrency() {
        assert_eq!(pool_size_for(8), 8);
        assert_eq!(pool_size_for(1), 1);
        // Zero concurrency would otherwise produce a zero-connection pool,
        // which cannot serve a single request.
        assert_eq!(pool_size_for(0), 1);
    }

    #[test]
    fn an_empty_result_is_an_error_not_a_measurement() {
        let err = ensure_non_empty(0, "point_lookup", 7).expect_err("empty result rejected");
        assert!(matches!(err, DirectError::EmptyResult { .. }));
        // The bracketed prefix survives so a log grep can classify it.
        assert!(err.to_string().starts_with("[BENCH_DIRECT_EMPTY_RESULT]"));
    }

    #[test]
    fn a_non_empty_result_passes() {
        ensure_non_empty(1, "point_lookup", 7).expect("one row is fine");
    }
}
