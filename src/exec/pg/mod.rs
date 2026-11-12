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
//! `PgConnectOptions` construction, `run` owns the per-query transaction
//! orchestration. `catalog`, `sample` and `explain` build the Postgres SQL
//! behind the matching `DbAdapter` methods. This file keeps only the adapter
//! shape.

mod cancel;
mod catalog;
mod config;
mod decode;
mod explain;
mod run;
mod sample;
mod truncate;

use std::time::Duration;

use async_trait::async_trait;
use metrics::gauge;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::config::{Database, Server};

use super::adapter::{
    AdapterKind, DbAdapter, ExecError, ExecQuery, ExecResult, ExplainQuery, SampleQuery,
    SchemaQuery, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms,
};

use config::build_connect_options;
use decode::classify;
use run::run_query_inner;

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

    async fn describe_schema(&self, query: SchemaQuery<'_>) -> Result<ExecResult, ExecError> {
        let (sql, binds) = catalog::columns_query(query.schema, query.table);
        self.execute(ExecQuery {
            sql: &sql,
            binds: &binds,
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: query.row_limit,
        })
        .await
    }

    async fn sample(&self, query: SampleQuery<'_>) -> Result<ExecResult, ExecError> {
        let sql = sample::sample_sql(query.schema, query.table, query.row_limit);
        self.execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: query.row_limit,
        })
        .await
    }

    async fn explain(&self, query: ExplainQuery<'_>) -> Result<ExecResult, ExecError> {
        let sql = explain::explain_sql(query.sql);
        self.execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: explain::EXPLAIN_RESULT_CAP,
        })
        .await
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
