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
//!    the pool (see [`reset_on_release`]).
//!
//! Split by responsibility: `tier` owns one role's pools, `cancel` owns the
//! identity-checked cancel and its drop guard, `truncate` owns
//! read-truncation cleanup, `decode` owns row → JSON, `error` owns
//! `sqlx::Error` → `ExecError`, `config` owns password resolution and
//! `PgConnectOptions` construction, `run` owns the per-query transaction.
//! `catalog`, `sample`, `explain` and `introspect` build the Postgres SQL
//! behind the matching `DbAdapter` methods.

mod cancel;
mod catalog;
mod config;
mod decode;
mod error;
mod explain;
mod introspect;
mod methods;
mod run;
mod sample;
mod tier;
mod truncate;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use sqlx::pool::{PoolConnection, PoolConnectionMetadata};
use sqlx::postgres::Postgres;
use sqlx::{Executor, PgConnection};
use uuid::Uuid;

use crate::audit::drain::DetachedTasks;
use crate::config::{Database, Server};

use super::adapter::{ExecError, ExecResult, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms};
use super::pool_sizing::PoolSizing;
use super::query::{ActivityQuery, ExecQuery};
use super::sql_guard::Access;

use error::{AcquireFailure, is_feature_not_supported, log_discarded};
use run::{RunCtx, run_query_inner};
use tier::Tier;

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

/// Per-`(server, database)` Postgres adapter: the read tier, plus the write
/// tier when the database has a `write_role`. One instance per logical DB so
/// a slow query on DB A can never block DB B.
pub struct PgAdapter {
    read: Tier,
    write: Option<Tier>,
    /// Set when the target rejected the credentials; the registry then
    /// replaces this adapter so the passwords are resolved again.
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
            .field("writable", &self.write.is_some())
            .finish()
    }
}

impl PgAdapter {
    /// Open the tiers for `(server, database)`. The read pool connects once
    /// so a misconfigured DB errors here (the registry calls this on first
    /// request to that DB, not at boot); the write and cancel pools connect
    /// on first use. Drop-guard cancels run on `detached`.
    pub async fn open(
        server: &Server,
        database: &Database,
        sizing: PoolSizing,
        detached: DetachedTasks,
    ) -> Result<Self, ExecError> {
        let db_label = format!("{}/{}", server.name, database.name);
        let read = Tier::open_read(server, database, sizing, &db_label).await?;
        let write = match database.write_credentials() {
            Some(credentials) => {
                Some(Tier::open_write(server, database, credentials, sizing, &db_label).await?)
            }
            None => None,
        };
        Ok(Self {
            read,
            write,
            stale: AtomicBool::new(false),
            detached,
            db_label,
        })
    }

    /// The tier a statement needing `access` runs on.
    fn tier(&self, access: Access) -> Result<&Tier, ExecError> {
        match access {
            Access::ReadOnly => Ok(&self.read),
            Access::ReadWrite => self.write.as_ref().ok_or(ExecError::WriteNotConfigured),
        }
    }

    /// The read tier, then the write tier if it ever connected.
    fn connected_tiers(&self) -> impl Iterator<Item = &Tier> {
        std::iter::once(&self.read).chain(self.write.iter().filter(|t| t.is_connected()))
    }

    /// A connection for one query, bounded by [`POOL_ACQUIRE_TIMEOUT`]. A
    /// credential rejection marks the adapter stale.
    async fn acquire(&self, tier: &Tier) -> Result<PoolConnection<Postgres>, ExecError> {
        tier.pool
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

    /// Run `query` on `tier` under the Tokio-side deadline. The transaction
    /// mode comes from `query.access`, not from the tier: `explain` of a
    /// write runs on the write tier in a read-only transaction.
    async fn run(&self, tier: &Tier, query: &ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        let mut conn = self.acquire(tier).await?;
        // Belt-and-suspenders: a Tokio-side deadline so even a misapplied
        // SET LOCAL (or a DB that ignores it) still bounds the call. Same
        // effective value as the DB-side cap set inside `run_query_inner`.
        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        let ctx = RunCtx {
            cancel_pool: &tier.cancel_pool,
            role: &tier.role,
            detached: &self.detached,
        };
        match tokio::time::timeout(budget, run_query_inner(&mut conn, &ctx, query)).await {
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
        self.run(&self.read, &query).await
    }

    /// `db_activity` for one tier: each role sees its own backends.
    async fn activity_on(
        &self,
        tier: &Tier,
        query: &ActivityQuery,
    ) -> Result<ExecResult, ExecError> {
        let sql = introspect::activity_sql(tier.kind);
        let exec = ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: query.statement_timeout_ms,
            row_limit: query.row_limit,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: query.request_id,
        };
        self.run(tier, &exec).await
    }
}

/// `after_release` hook: wipe session state before a connection serves the
/// next caller. `RESET ALL` undoes session `SET`s / `set_config(…, false)`;
/// `pg_advisory_unlock_all()` drops session advisory locks. Not `DISCARD
/// ALL`: it would also drop the prepared statements sqlx's cache still
/// believes exist. A failed reset discards the connection.
///
/// A server without advisory locks (YugabyteDB with the preview flag off)
/// rejects the unlock as `feature_not_supported`; it can hold no advisory
/// lock, so the connection is kept. The rejected statement aborted the
/// implicit transaction the pair ran in, taking `RESET ALL` with it, so the
/// reset is repeated alone.
fn reset_on_release(
    conn: &mut PgConnection,
    _meta: PoolConnectionMetadata,
) -> BoxFuture<'_, Result<bool, sqlx::Error>> {
    Box::pin(async move {
        let reset = match conn
            .execute("RESET ALL; SELECT pg_advisory_unlock_all()")
            .await
        {
            Err(err) if is_feature_not_supported(&err) => conn.execute("RESET ALL").await,
            other => other,
        };
        match reset {
            Ok(_) => Ok(true),
            Err(err) => {
                log_discarded(&err, "connection reset failed; discarding");
                Ok(false)
            }
        }
    })
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
