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
//! 3. A read runs in a `READ ONLY` transaction, and no session state
//!    survives a connection's return to the pool (see [`reset_on_release`]).
//!
//! Split by responsibility: `cancel` owns the identity-checked cancel and
//! its drop guard, `truncate` owns read-truncation cleanup, `decode` owns
//! row → JSON, `error` owns `sqlx::Error` → `ExecError`, `config` owns
//! password resolution and `PgConnectOptions` construction, `run` owns the
//! per-query transaction. `catalog`, `sample` and `explain` build the
//! Postgres SQL behind the matching `DbAdapter` methods.

mod cancel;
mod catalog;
mod config;
mod decode;
mod error;
mod explain;
mod run;
mod sample;
mod truncate;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures::future::BoxFuture;
use metrics::gauge;
use sqlx::pool::{PoolConnection, PoolConnectionMetadata};
use sqlx::postgres::{PgPoolOptions, Postgres};
use sqlx::{Executor, PgConnection, PgPool};

use crate::audit::drain::DetachedTasks;
use crate::config::{Database, Server};

use super::adapter::{
    DbAdapter, ExecError, ExecQuery, ExecResult, ExplainQuery, SampleQuery, SchemaQuery,
    TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms,
};
use super::pool_sizing::PoolSizing;
use super::sql_guard::Access;

use config::build_connect_options;
use error::{AcquireFailure, log_discarded};
use run::{RunCtx, run_query_inner};

// Re-exported so `super::pg::resolve_password` keeps working for sibling
// adapters (mongo::MongoAdapter::open) without exposing the config submodule.
pub(crate) use config::resolve_password;

/// Bound on waiting for a pooled connection (or opening one). Spent *before*
/// the statement budget starts: a saturated pool is `unavailable`, not a
/// `timeout` of the caller's query.
pub(super) const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Dedicated pool for `pg_cancel_backend(pid)`. Must stay separate
/// from the main pool — if `CancelOnDrop::drop` fired through the main
/// pool, its `execute` would queue on `acquire()` behind the very
/// connections the cancels are trying to free (N hung queries + N drops
/// with `max_connections = N` deadlocks every cancel until
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
    /// Redacted from server messages before they reach the agent.
    role: String,
    /// Set when the target rejected the credentials; the registry then
    /// replaces this adapter so the password is resolved again.
    stale: AtomicBool,
    /// Tracks drop-guard cancels so a shutdown drain waits for them.
    detached: DetachedTasks,
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
    /// Open the pools for `(server, database)`. The query pool connects once
    /// so a misconfigured DB errors here (the registry calls this on first
    /// request to that DB, not at boot); that connection then idles out like
    /// any other. The cancel pool connects on first use. Drop-guard cancels
    /// run on `detached`.
    pub async fn open(
        server: &Server,
        database: &Database,
        sizing: PoolSizing,
        detached: DetachedTasks,
    ) -> Result<Self, ExecError> {
        let password = resolve_password(&database.password).await?;
        let opts = build_connect_options(server, database, &password);
        let pool = PgPoolOptions::new()
            .max_connections(sizing.max_connections)
            .min_connections(sizing.min_connections)
            .idle_timeout(sizing.idle_timeout)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .after_release(reset_on_release)
            .connect_with(opts.clone())
            .await
            .map_err(|err| {
                log_discarded(&err, "target pool open failed");
                ExecError::Connection
            })?;
        let cancel_pool = PgPoolOptions::new()
            .max_connections(CANCEL_POOL_MAX_CONNECTIONS)
            .min_connections(0)
            .idle_timeout(sizing.idle_timeout)
            .acquire_timeout(POOL_ACQUIRE_TIMEOUT)
            .connect_lazy_with(opts);

        let db_label = format!("{}/{}", server.name, database.name);
        // Configured maxima, one gauge per pool kind — cheap first signal for
        // "pool exists for this db" with bounded label cardinality.
        gauge!("pool_size", "db" => db_label.clone(), "pool_kind" => "query")
            .set(f64::from(sizing.max_connections));
        gauge!("pool_size", "db" => db_label.clone(), "pool_kind" => "cancel")
            .set(f64::from(CANCEL_POOL_MAX_CONNECTIONS));

        Ok(Self {
            pool,
            cancel_pool,
            role: database.role.clone(),
            stale: AtomicBool::new(false),
            detached,
            db_label,
        })
    }

    /// A connection for one query, bounded by [`POOL_ACQUIRE_TIMEOUT`]. A
    /// credential rejection marks the adapter stale.
    async fn acquire(&self) -> Result<PoolConnection<Postgres>, ExecError> {
        self.pool
            .acquire()
            .await
            .map_err(|err| match AcquireFailure::of(&err) {
                AcquireFailure::Auth => {
                    self.stale.store(true, Ordering::Relaxed);
                    ExecError::Connection
                }
                AcquireFailure::Other => ExecError::Unavailable,
            })
    }
}

/// `after_release` hook: wipe session state before a connection serves the
/// next caller. `RESET ALL` undoes session `SET`s / `set_config(…, false)`;
/// `pg_advisory_unlock_all()` drops session advisory locks. Not `DISCARD
/// ALL`: it would also drop the prepared statements sqlx's cache still
/// believes exist. A failed reset discards the connection.
fn reset_on_release(
    conn: &mut PgConnection,
    _meta: PoolConnectionMetadata,
) -> BoxFuture<'_, Result<bool, sqlx::Error>> {
    Box::pin(async move {
        match conn
            .execute("RESET ALL; SELECT pg_advisory_unlock_all()")
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                log_discarded(&err, "connection reset failed; discarding");
                Ok(false)
            }
        }
    })
}

#[async_trait]
impl DbAdapter for PgAdapter {
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        let mut conn = self.acquire().await?;
        // Belt-and-suspenders: a Tokio-side deadline so even a misapplied
        // SET LOCAL (or a DB that ignores it) still bounds the call. Same
        // effective value as the DB-side cap set inside `run_query_inner`.
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        let ctx = RunCtx {
            cancel_pool: &self.cancel_pool,
            role: &self.role,
            detached: &self.detached,
        };
        match tokio::time::timeout(budget, run_query_inner(&mut conn, &ctx, &query)).await {
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
            access: Access::ReadOnly,
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
            access: Access::ReadOnly,
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
            access: Access::ReadOnly,
        })
        .await
    }

    fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
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
