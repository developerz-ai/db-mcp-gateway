//! Redis-protocol target adapter (Redis, Dragonfly, Valkey, KeyDB) —
//! read-only enforcement + command execution.
//!
//! Wire shape: [`RedisAdapter`] implements [`super::DbAdapter`] and is
//! dispatched to by [`super::AdapterRegistry`] when `server.kind` is
//! [`crate::config::ServerKind::Redis`]. The command travels in
//! `ExecQuery::sql` as a JSON array argv (`["HGETALL","user:1"]`); the
//! [`rejector`] accepts only allowlisted read commands, before any network
//! call. Writes are never offered, whatever the grant says.
//!
//! Security-required (CLAUDE.md). No connection URL is ever built: the client
//! is assembled from structured parts (host, port, ACL user, password, db
//! index), and the hand-rolled `Debug` prints only the `server/db` label.

mod bounded;
mod db_index;
mod error;
mod pool;
pub mod rejector;
mod shape;
mod value_json;

pub use db_index::RedisDbIndex;
pub use shape::{ScanItem, Shape};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use redis::{Client, ConnectionAddr, IntoConnectionInfo, RedisConnectionInfo, TlsCertificates};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::config::{Database, Server, Tls};

use super::adapter::{AdapterKind, DbAdapter, ExecError, ExecResult, effective_timeout_ms};
use super::pg::resolve_password;
use super::pool_sizing::{CallerSlots, PoolSizing};
use super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};
use bounded::{BoundError, Fetched};
use error::{connection_lost, connection_survives};
use pool::{ConnPool, Lease};
use rejector::Command;
use shape::{Shaped, shape_reply};

/// Bound on waiting for a pooled connection, or opening one — spent before
/// the statement budget starts. Same value and meaning as the Postgres
/// adapter's acquire timeout.
const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-`(server, database)` Redis adapter: one pool per logical database, so
/// a slow command on one never blocks another.
pub struct RedisAdapter {
    pool: Arc<ConnPool>,
    /// Each caller's share of `pool`.
    callers: CallerSlots,
    /// `server/db` for logs — from config, bounded cardinality.
    db_label: String,
    /// The ACL username, redacted out of every server message.
    role: String,
    /// Set when the server rejected the credentials; the registry then
    /// replaces this adapter so the password is resolved again.
    stale: AtomicBool,
}

impl std::fmt::Debug for RedisAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `redis::Client`'s `Debug` would render the connection info. Never
        // let that leak — print structural info only, as `MongoAdapter` does.
        f.debug_struct("RedisAdapter")
            .field("db", &self.db_label)
            .finish()
    }
}

impl RedisAdapter {
    /// Build the client for `(server, database)`. Lazy: no connection opens
    /// until the first command, so a misconfigured target fails on use, not
    /// at boot. `tls: required` and `verify_full` both verify the server
    /// certificate (as Mongo does); `tls_ca_file` replaces the system roots.
    pub async fn open(
        server: &Server,
        database: &Database,
        sizing: PoolSizing,
    ) -> Result<Self, ExecError> {
        let db_label = format!("{}/{}", server.name, database.name);
        // Boot validation already refused a non-index name; a backstop only.
        let Some(index) = RedisDbIndex::parse(&database.name) else {
            tracing::warn!(db = %db_label, "redis database name is not a db index");
            return Err(ExecError::Connection);
        };
        let password = resolve_password(&database.password).await?;
        let addr = match server.tls {
            Tls::Insecure => ConnectionAddr::Tcp(server.host.clone(), server.port),
            Tls::Required | Tls::VerifyFull => ConnectionAddr::TcpTls {
                host: server.host.clone(),
                port: server.port,
                insecure: false,
                tls_params: None,
            },
        };
        // The driver boundary: the plaintext password is exposed only here.
        let settings = RedisConnectionInfo::default()
            .set_username(&database.role)
            .set_password(password.expose_secret())
            .set_db(i64::from(index.get()))
            // `CLIENT SETINFO` needs a permission a read-only ACL user lacks.
            .set_skip_set_lib_name();
        let info = addr
            .into_connection_info()
            .map_err(|_| ExecError::Connection)?
            .set_redis_settings(settings);
        let client = match &server.tls_ca_file {
            Some(path) => {
                let root_cert = tokio::fs::read(path).await.map_err(|_| {
                    tracing::warn!(db = %db_label, "redis tls_ca_file unreadable");
                    ExecError::Connection
                })?;
                let certificates = TlsCertificates {
                    client_tls: None,
                    root_cert: Some(root_cert),
                };
                Client::build_with_tls(info, certificates)
            }
            None => Client::open(info),
        }
        .map_err(|_| ExecError::Connection)?;
        Ok(Self {
            pool: ConnPool::new(client, sizing),
            callers: CallerSlots::new(sizing),
            db_label,
            role: database.role.clone(),
            stale: AtomicBool::new(false),
        })
    }

    /// A pooled connection, waited for at most [`POOL_ACQUIRE_TIMEOUT`] —
    /// outside the statement budget, as on Postgres: a saturated pool is
    /// `unavailable`, never a `timeout` of the caller's command.
    async fn lease(&self) -> Result<Lease, ExecError> {
        match tokio::time::timeout(POOL_ACQUIRE_TIMEOUT, self.pool.lease()).await {
            Ok(Ok(lease)) => Ok(lease),
            Ok(Err(err)) => Err(self.classify_connect(err)),
            Err(_elapsed) => {
                tracing::warn!(db = %self.db_label, "redis pool acquire timed out");
                Err(ExecError::Unavailable)
            }
        }
    }

    /// Run one accepted command bounded to `row_limit` and shape the reply.
    /// A pooled connection found closed is replaced once and the command run
    /// again on the new one. The connection goes back to the pool only after
    /// complete replies; if
    /// this future is dropped mid-command (timeout, agent disconnect) the
    /// lease drops with it and the connection is closed, never reused.
    async fn run(
        &self,
        mut lease: Lease,
        command: Command,
        row_limit: u32,
    ) -> Result<ExecResult, ExecError> {
        let started = Instant::now();
        let mut outcome = bounded::fetch(lease.conn(), &command, row_limit).await;
        if let Err(BoundError::Redis(err)) = &outcome
            && lease.reused()
            && connection_lost(err)
        {
            // The pooled connection was closed while idle. Every command the
            // rejector admits is a read, so running it again is safe.
            tracing::debug!(db = %self.db_label, "idle redis connection was closed; reconnecting");
            lease
                .reconnect()
                .await
                .map_err(|err| self.classify_connect(err))?;
            outcome = bounded::fetch(lease.conn(), &command, row_limit).await;
        }
        let fetched = match outcome {
            Ok(fetched) => {
                lease.release().await;
                fetched
            }
            Err(BoundError::Refused(reason)) => {
                lease.release().await;
                return Err(ExecError::Forbidden(reason));
            }
            Err(BoundError::Redis(err)) => {
                if connection_survives(&err) {
                    lease.release().await;
                }
                return Err(self.classify_command(err));
            }
        };
        let shaped = match fetched {
            Fetched::Reply(reply) => shape_reply(command.shape, reply, row_limit)?,
            Fetched::Partial(reply) => Shaped {
                truncated: true,
                ..shape_reply(command.shape, reply, row_limit)?
            },
            // Only single-value commands (shape `value`) answer `TooLarge`.
            Fetched::TooLarge => Shaped {
                columns: vec!["value".to_string()],
                rows: Vec::new(),
                truncated: true,
            },
        };
        Ok(ExecResult {
            columns: shaped.columns,
            column_types: Vec::new(),
            rows: shaped.rows,
            truncated: shaped.truncated,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            rows_affected: None,
        })
    }
}

#[async_trait]
impl DbAdapter for RedisAdapter {
    /// Rejector first: a refused command maps to [`ExecError::Forbidden`]
    /// (→ `forbidden_sql`) and never reaches the network. Redis targets are
    /// read-only whatever `query.access` says.
    ///
    /// **Timeout** — Redis has no per-command server-side timeout, so the
    /// gateway budget ([`effective_timeout_ms`]) is enforced client-side
    /// over the command (and any precheck it needs); on expiry the
    /// connection is discarded with the dropped future. Waiting for a pooled
    /// connection is bounded separately (`lease`).
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        let command = rejector::validate_command(query.sql)
            .map_err(|err| ExecError::Forbidden(err.to_string()))?;
        // The caller's share of the pool first, as on Postgres.
        let _slot = self.callers.take(POOL_ACQUIRE_TIMEOUT).await?;
        let lease = self.lease().await?;
        let budget =
            Duration::from_millis(u64::from(effective_timeout_ms(query.statement_timeout_ms)));
        match tokio::time::timeout(budget, self.run(lease, command, query.row_limit)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    async fn describe_schema(&self, _query: SchemaQuery<'_>) -> Result<ExecResult, ExecError> {
        Err(unsupported("describe_schema"))
    }

    async fn sample(&self, _query: SampleQuery<'_>) -> Result<ExecResult, ExecError> {
        Err(unsupported("sample"))
    }

    async fn explain(&self, _query: ExplainQuery<'_>) -> Result<ExecResult, ExecError> {
        Err(unsupported("explain"))
    }

    async fn table_stats(&self, _query: TableStatsQuery<'_>) -> Result<ExecResult, ExecError> {
        Err(unsupported("table_stats"))
    }

    async fn db_activity(&self, _query: ActivityQuery) -> Result<ExecResult, ExecError> {
        Err(unsupported("db_activity"))
    }

    async fn cancel_request(&self, _request_id: Uuid) -> Result<bool, ExecError> {
        Err(unsupported("cancel_request"))
    }

    fn is_stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }
}

fn unsupported(op: &'static str) -> ExecError {
    ExecError::NotImplemented {
        adapter: AdapterKind::Redis,
        op,
    }
}
