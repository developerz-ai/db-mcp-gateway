//! The baseline path: the same SQL, straight at Postgres over sqlx.
//!
//! This is what the gateway is measured *against*, so it must be as fast as a
//! well-written application would be — a slow baseline flatters the gateway.
//! Hence a warm pool sized to the driver's concurrency, and no per-request
//! connect. Anything that makes this path artificially slow makes the
//! published overhead artificially small, which is the failure mode this whole
//! exercise exists to avoid.

use std::time::Instant;

use sqlx::{Row, postgres::PgPoolOptions};

use crate::workload::{Shape, postgres_seed};

#[derive(Debug, thiserror::Error)]
pub enum DirectError {
    #[error("direct database access failed: {0}")]
    Db(#[from] sqlx::Error),
    /// The query succeeded but returned nothing. `RowNotFound` would render as
    /// a database failure, which points an operator at connectivity instead of
    /// at the query shape — and a benchmark measuring an empty result set is
    /// measuring a no-op.
    #[error("shape {shape} returned no rows at iteration {iteration}")]
    EmptyResult { shape: &'static str, iteration: u64 },
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
        let pool = PgPoolOptions::new()
            .max_connections(concurrency.max(1))
            .min_connections(concurrency.max(1))
            .connect(url)
            .await?;
        Ok(DirectClient { pool })
    }

    /// Create and populate the benchmark table.
    ///
    /// **Destructive.** The DDL opens with `DROP TABLE IF EXISTS bench_rows`,
    /// so any existing `bench_rows` in the target database is discarded. Point
    /// the harness at a disposable database only. The drop is what makes a
    /// re-run measure the same bytes rather than appending to the previous
    /// run's data.
    pub async fn seed(&self) -> Result<(), DirectError> {
        // `execute` on a multi-statement string runs it as one implicit
        // transaction, which is what we want: a half-seeded table would make
        // every subsequent number meaningless.
        sqlx::raw_sql(&postgres_seed()).execute(&self.pool).await?;
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
        if rows.is_empty() {
            return Err(DirectError::EmptyResult {
                shape: shape.name(),
                iteration,
            });
        }

        Ok(elapsed)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}
