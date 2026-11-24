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
//! 3. A read runs as the database's read `role` in a `READ ONLY`
//!    transaction; only `Access::ReadWrite` reaches the write tier
//!    (`write_role`). No session state survives a connection's return to
//!    the pool (see `release`).
//! 4. Memory is bounded per query, not per cell: a row past the result
//!    budget is refused from its wire length, before it is decoded (see
//!    `stream`). The driver has still buffered that one row — up to
//!    Postgres' 1 GiB row limit — and the buffer is given back on release.
//!
//! Split by responsibility: `tier` owns one role's pools, `cancel` owns the
//! identity-checked cancel and its drop guard, `truncate` owns
//! read-truncation cleanup, `decode` owns row → JSON, `error` owns
//! `sqlx::Error` → `ExecError`, `config` owns password resolution and
//! `PgConnectOptions` construction, `release` owns the session reset between
//! callers, `run` owns the per-query transaction,
//! `stream` owns row collection against the result budget, `recast` owns the
//! second attempt at a read whose columns have no binary form, `near_miss`
//! owns the names offered for an undefined table or column.
//! `catalog`, `sample`, `explain` and `introspect` build the Postgres SQL
//! behind the matching `DbAdapter` methods.

mod cancel;
mod cancel_pool;
mod catalog;
mod catalog_full;
mod config;
mod decode;
mod error;
mod explain;
mod introspect;
mod methods;
mod near_miss;
pub(crate) mod pool_metrics;
mod recast;
mod redact;
mod release;
mod run;
mod sample;
mod stream;
mod tier;
mod truncate;

use std::sync::Arc;
use std::time::Duration;

use sqlx::pool::PoolConnection;
use sqlx::postgres::Postgres;
use sqlx::{PgConnection, PgPool};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::audit::drain::DetachedTasks;
use crate::config::{Database, Server};

use super::adapter::{ExecError, ExecResult, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms};
use super::pool_sizing::PoolSizing;
use super::query::{ExecQuery, QueryParam};
use super::sql_guard::Access;

use error::{AcquireFailure, Origin};
use run::{RunCtx, run_query};
use stream::LARGE_ROW_DECODES;
use tier::{Tier, WriteTier};

// Re-exported so `super::pg::resolve_password` keeps working for sibling
// adapters (mongo::MongoAdapter::open) without exposing the config submodule.
pub use cancel_pool::{InvalidCancelPoolSize, init_cancel_pool_size_from_env};
pub(crate) use config::resolve_password;

/// Bound on waiting for a pooled connection (or opening one). Spent *before*
/// the statement budget starts: a saturated pool is `unavailable`, not a
/// `timeout` of the caller's query.
pub(super) const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-`(server, database)` Postgres adapter: the read tier, plus the write
/// tier when the database has a `write_role`. One instance per logical DB so
/// a slow query on DB A can never block DB B.
pub struct PgAdapter {
    /// Its staleness is the adapter's: when the target rejects the read
    /// credentials the registry replaces the adapter. The write tier is
    /// replaced on its own (see [`WriteTier`]).
    read: Arc<Tier>,
    write: Option<WriteTier>,
    /// Tracks drop-guard cancels so a shutdown drain waits for them.
    detached: DetachedTasks,
    /// Bounds how many large rows are being decoded at once, across both
    /// tiers (see `stream`).
    large_rows: Semaphore,
    /// Named on the log line of every target error.
    server: String,
    database: String,
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
            .field("writable", &self.write.is_some())
            .finish()
    }
}

impl PgAdapter {
    /// Open the adapter for `(server, database)`. The read pool connects
    /// once so a misconfigured DB errors here (the registry calls this on
    /// first request to that DB, not at boot); the write tier resolves its
    /// password and connects on first use, and every cancel pool connects on
    /// first use. Drop-guard cancels run on `detached`.
    pub async fn open(
        server: &Server,
        database: &Database,
        sizing: PoolSizing,
        detached: DetachedTasks,
    ) -> Result<Self, ExecError> {
        let db_label = format!("{}/{}", server.name, database.name);
        let read = Tier::open_read(server, database, sizing, &db_label).await?;
        let write = database
            .write_credentials()
            .map(|credentials| WriteTier::new(server, database, credentials, sizing, &db_label));
        Ok(Self {
            read,
            write,
            detached,
            large_rows: Semaphore::new(LARGE_ROW_DECODES),
            server: server.name.clone(),
            database: database.name.clone(),
            db_label,
        })
    }

    /// The tier a statement needing `access` runs on.
    async fn tier(&self, access: Access) -> Result<Arc<Tier>, ExecError> {
        match access {
            Access::ReadOnly => Ok(Arc::clone(&self.read)),
            Access::ReadWrite => self.write_tier().await,
        }
    }

    async fn write_tier(&self) -> Result<Arc<Tier>, ExecError> {
        match &self.write {
            Some(write) => write.get().await,
            None => Err(ExecError::WriteNotConfigured),
        }
    }

    fn origin<'a>(&'a self, tier: &'a Tier, request_id: Uuid) -> Origin<'a> {
        Origin {
            server: &self.server,
            database: &self.database,
            role: &tier.role,
            request_id: Some(request_id),
        }
    }

    /// A connection from one of `tier`'s pools, bounded by
    /// [`POOL_ACQUIRE_TIMEOUT`]. The one place a connect-phase error is
    /// handled: it is never rendered (it can name the role and the client
    /// address), and a credential rejection marks that tier — only that
    /// tier — stale.
    async fn acquire(
        &self,
        tier: &Tier,
        pool: &PgPool,
        request_id: Uuid,
    ) -> Result<PoolConnection<Postgres>, ExecError> {
        let started = std::time::Instant::now();
        let acquired = pool.acquire().await;
        pool_metrics::record_acquire_wait(&self.db_label, tier.pool_kind(pool), started.elapsed());
        acquired.map_err(
            |err| match AcquireFailure::of(&err, &self.origin(tier, request_id)) {
                AcquireFailure::Auth => {
                    tier.mark_stale();
                    ExecError::Connection
                }
                AcquireFailure::Other => ExecError::Unavailable,
            },
        )
    }

    /// Run `query` on `tier`'s query pool. The transaction mode comes from
    /// `query.access`, not from the tier: `explain` of a write runs on the
    /// write tier in a read-only transaction.
    /// `params` are the caller's, bound after `query.binds`.
    async fn run(
        &self,
        tier: &Tier,
        query: &ExecQuery<'_>,
        params: &[QueryParam],
    ) -> Result<ExecResult, ExecError> {
        // The caller's share of the pool first, so a caller at its share
        // waits on itself rather than taking the connection others need.
        let _slot = tier.callers.take(POOL_ACQUIRE_TIMEOUT).await?;
        let mut conn = self.acquire(tier, &tier.pool, query.request_id).await?;
        self.run_on(&mut conn, tier, query, params).await
    }

    /// Run `query` on `conn`, a connection of `tier`, under the Tokio-side
    /// deadline.
    async fn run_on(
        &self,
        conn: &mut PgConnection,
        tier: &Tier,
        query: &ExecQuery<'_>,
        params: &[QueryParam],
    ) -> Result<ExecResult, ExecError> {
        // Belt-and-suspenders: a Tokio-side deadline so even a misapplied
        // SET LOCAL (or a DB that ignores it) still bounds the call. Same
        // effective value as the DB-side cap set inside `run_query`.
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        let ctx = RunCtx {
            cancel_pool: &tier.cancel_pool,
            origin: self.origin(tier, query.request_id),
            detached: &self.detached,
            large_rows: &self.large_rows,
        };
        match tokio::time::timeout(budget, run_query(conn, &ctx, query, params)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    /// A gateway-built read on the read tier: catalog, sample, statistics.
    async fn run_read(
        &self,
        sql: &str,
        binds: &[&str],
        statement_timeout_ms: Option<u32>,
        row_limit: u32,
        request_id: Uuid,
    ) -> Result<ExecResult, ExecError> {
        let query = ExecQuery {
            sql,
            binds,
            statement_timeout_ms,
            row_limit,
            access: Access::ReadOnly,
            dry_run: false,
            request_id,
        };
        self.run(&self.read, &query, &[]).await
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
