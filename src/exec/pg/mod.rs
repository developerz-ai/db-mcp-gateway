//! Postgres adapter — `DbAdapter` impl plus the per-DB pool open path.
//!
//! Security non-negotiables (CLAUDE.md):
//!
//! 1. The connection password (literal, env-resolved, or backend-resolved) is
//!    NEVER embedded in `Display` for any error or in any tracing field on
//!    the request path. The DSN we build is fed to `sqlx` and dropped.
//! 2. The DB-side `statement_timeout` is set via `SET LOCAL` inside the
//!    per-query transaction, so a single misuse can't outlive its tx. We also
//!    wrap the query in `tokio::time::timeout` as belt-and-suspenders — if
//!    the DB ignores `SET LOCAL`, the future still completes. A timeout is
//!    ALWAYS applied: a grant that declines to cap (or asks for more than
//!    the gateway allows) is resolved by
//!    [`super::adapter::effective_timeout_ms`], so no query can pin a pool
//!    connection indefinitely and no grant can loosen past the ceiling.
//!
//! Split by responsibility: `cancel` owns the drop-guard cancellation,
//! `truncate` owns the row-cap cleanup, `decode` owns row → JSON and
//! `sqlx::Error` → `ExecError`, `config` owns password resolution and
//! `PgConnectOptions` construction. This file keeps only the adapter shape
//! and `run_query_inner` orchestration.

mod cancel;
mod config;
mod decode;
mod truncate;

use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt;
use metrics::gauge;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Column, Executor, PgPool, Row};

use crate::config::{Database, Server};

use super::adapter::{
    AdapterKind, DbAdapter, ExecError, ExecQuery, ExecResult, TOKIO_TIMEOUT_SLACK_MS,
    effective_timeout_ms,
};

use cancel::CancelOnDrop;
use config::build_connect_options;
use decode::{classify, decode_row};
use truncate::cancel_and_rollback;

// Re-exported so `super::pg::resolve_password` keeps working for sibling
// adapters (mongo::MongoAdapter::open) without exposing the config submodule.
pub(crate) use config::resolve_password;

/// Public so integration tests (e.g. `cancellation_real_db`) can size the
/// saturation workload to match the pool exactly rather than duplicating the
/// literal — a stale copy would silently stop exercising full saturation if
/// this constant changed.
pub const DEFAULT_POOL_MAX_CONNECTIONS: u32 = 5;
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Dedicated pool for `pg_cancel_backend(pid)` writes. Must stay separate
/// from the main pool — if `CancelOnDrop::drop` fired through the main
/// pool, its `execute` would queue on `acquire()` behind the very
/// connections the cancels are trying to free (five hung queries + five
/// drops with `max_connections = 5` deadlocks every cancel until
/// `statement_timeout` expires). Sized to 2 so a burst of concurrent
/// disconnects gets two round-trips in parallel; cancels are single-round
/// and cheap, no need for more.
pub(super) const CANCEL_POOL_MAX_CONNECTIONS: u32 = 2;

/// Per-`(server, database)` Postgres adapter. Wraps a `PgPool`; one instance
/// per logical DB so a slow query on DB A can never block DB B.
pub struct PgAdapter {
    pool: PgPool,
    /// Dedicated pool for `pg_cancel_backend(pid)`. Never shares connections
    /// with `pool` — see [`CANCEL_POOL_MAX_CONNECTIONS`] for the reason.
    cancel_pool: PgPool,
    /// Composite label for metrics tagging — bounded cardinality, supplied
    /// from YAML config rather than user input.
    db_label: String,
}

impl std::fmt::Debug for PgAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `PgPool`'s derived `Debug` exposes the connection URL with password.
        // Never let that leak — print structural info only.
        f.debug_struct("PgAdapter")
            .field("db", &self.db_label)
            .finish()
    }
}

impl PgAdapter {
    /// Open a fresh pool for `(server, database)`. Lazy: a misconfigured DB
    /// only errors here (the registry calls this on first request to that
    /// DB), not at boot.
    pub async fn open(server: &Server, database: &Database) -> Result<Self, ExecError> {
        let password = resolve_password(&database.password).await?;
        let opts = build_connect_options(server, database, &password);
        // Same DSN for both pools — the cancel pool is a Postgres client like
        // any other, it just never runs anything but `pg_cancel_backend(...)`.
        let pool = PgPoolOptions::new()
            .max_connections(DEFAULT_POOL_MAX_CONNECTIONS)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_with(opts.clone())
            .await
            .map_err(|_| ExecError::Connection)?;
        let cancel_pool = PgPoolOptions::new()
            .max_connections(CANCEL_POOL_MAX_CONNECTIONS)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_with(opts)
            .await
            .map_err(|_| ExecError::Connection)?;

        let db_label = format!("{}/{}", server.name, database.name);
        // Single label `db = "<server>/<database>"` — bounded cardinality.
        // Live connection count would need a polling task; reporting the
        // configured max is the cheap first signal for "pool exists for this
        // db". A separate `pool_kind` label distinguishes the query pool from
        // the cancel pool so operator dashboards see both without stat name
        // proliferation.
        gauge!("pool_size", "db" => db_label.clone(), "pool_kind" => "query")
            .set(DEFAULT_POOL_MAX_CONNECTIONS as f64);
        gauge!("pool_size", "db" => db_label.clone(), "pool_kind" => "cancel")
            .set(CANCEL_POOL_MAX_CONNECTIONS as f64);

        Ok(Self {
            pool,
            cancel_pool,
            db_label,
        })
    }
}

#[async_trait]
impl DbAdapter for PgAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Postgres
    }

    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        // A timeout is ALWAYS applied: the grant value when present (it may be
        // tighter), else the gateway ceiling. `None` would otherwise leave the
        // query unbounded and pin a pool connection — see S4. Both the
        // DB-side `SET LOCAL` and this Tokio guard use the same effective
        // value (computed again inside `run_query_inner`).
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        // Belt-and-suspenders: a Tokio-side deadline so even a misapplied
        // SET LOCAL (or a DB that ignores it) still bounds the call.
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        match tokio::time::timeout(
            budget,
            run_query_inner(&self.pool, &self.cancel_pool, &query),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    async fn health(&self) -> Result<(), ExecError> {
        // `SELECT 1` proves the pool can hand out a working connection and
        // the DB is accepting queries. Cheaper than a no-op acquire because
        // the round-trip catches half-open connections too.
        sqlx::query("SELECT 1")
            .fetch_optional(&self.pool)
            .await
            .map(|_| ())
            .map_err(classify)
    }
}

async fn run_query_inner(
    pool: &PgPool,
    cancel_pool: &PgPool,
    query: &ExecQuery<'_>,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let mut tx = pool.begin().await.map_err(|_| ExecError::Unavailable)?;

    // Capture this connection's backend PID so a drop (agent disconnect) can
    // cancel the exact backend running our query — dropping `tx` alone won't
    // stop it. Armed now and disarmed only after a clean commit below. The
    // guard holds the *cancel* pool so `pg_cancel_backend` can always
    // acquire, even when every connection in the query pool is pinned by
    // stuck backends.
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .map_err(classify)?;
    let mut cancel = CancelOnDrop::armed(cancel_pool.clone(), pid);

    // Run the statement under the guard. By the time this block resolves — Ok
    // OR Err — the backend has stopped executing our query, so we disarm
    // before returning. The guard stays armed ONLY if this future is dropped
    // while awaiting (agent disconnect / outer `tokio::time::timeout`): the
    // one case where the backend is still running and must be cancelled.
    // Disarming on every normal return prevents a stray `pg_cancel_backend(pid)`
    // from cancelling an unrelated statement that later reuses this pooled
    // backend (same PID) — a flake where a timeout's detached cancel landed
    // mid-next-query and turned a healthy result into a spurious error.
    let result: Result<ExecResult, ExecError> = async {
        // Always set a DB-side cap — the grant value clamped to the gateway
        // ceiling, never `None` (see S4). `ms` is u32, so the SQL fragment is
        // purely a number — no injection risk from interpolation.
        let ms = effective_timeout_ms(query.statement_timeout_ms);
        let stmt = format!("SET LOCAL statement_timeout = {ms}");
        tx.execute(stmt.as_str()).await.map_err(classify)?;

        let limit = query.row_limit as usize;
        let mut columns: Vec<String> = Vec::new();
        let mut rows: Vec<Vec<Value>> = Vec::new();
        let mut truncated = false;

        {
            let mut sqlx_query = sqlx::query(query.sql);
            for bind in query.binds {
                sqlx_query = sqlx_query.bind(*bind);
            }
            let mut stream = sqlx_query.fetch(&mut *tx);
            while let Some(row_result) = stream.next().await {
                let row = row_result.map_err(classify)?;
                if columns.is_empty() {
                    columns = row.columns().iter().map(|c| c.name().to_string()).collect();
                }
                if rows.len() >= limit {
                    truncated = true;
                    break;
                }
                rows.push(decode_row(&row));
            }
            // Stream is dropped here so the borrow on `tx` ends.
        }

        // A zero-row result never enters the loop above, so `columns` would
        // stay empty and the caller could not tell "your filter matched
        // nothing" from "that table has no such columns" (#136). Ask the
        // server to describe the statement — Parse/Describe only, the query
        // does not run a second time.
        //
        // Best-effort on purpose: the query already succeeded, so a failure
        // here must not turn a good 0-row answer into an error. Worst case we
        // fall back to the previous (empty) behaviour.
        if columns.is_empty()
            && let Ok(described) = tx.describe(query.sql).await
        {
            columns = described
                .columns()
                .iter()
                .map(|c| c.name().to_string())
                .collect();
        }

        if truncated {
            // Truncation cleanup: cancel the backend so it stops generating
            // rows nobody asked for, then rollback the (now-aborted) tx.
            // Cleanup failures are logged at `warn` but do NOT fail the
            // request — see [`truncate::cancel_and_rollback`] and
            // `website/docs/initial-idea/05-credentials.md` for the contract.
            cancel_and_rollback(tx, cancel_pool, pid).await;
        } else {
            tx.commit().await.map_err(classify)?;
        }

        Ok(ExecResult {
            columns,
            rows,
            truncated,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }
    .await;
    // Statement finished (success or error) — no orphaned backend to cancel.
    cancel.disarm();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_error_display_carries_no_secrets() {
        let e = ExecError::PasswordUnresolved {
            kind: "env",
            reference: "MY_VAR".into(),
        };
        let s = format!("{e}");
        // Reference name is operationally useful and not itself a secret.
        assert!(s.contains("MY_VAR"));
        // Other variants must not leak details.
        assert_eq!(
            format!("{}", ExecError::Connection),
            "connection to target DB failed"
        );
        assert_eq!(
            format!("{}", ExecError::Timeout),
            "query exceeded the configured statement_timeout"
        );
    }
}
