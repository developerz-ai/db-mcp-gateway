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
use super::pool_sizing::PoolSizing;
use super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};
use error::connection_survives;
use pool::ConnPool;
use rejector::Command;
use shape::shape_reply;

/// Per-`(server, database)` Redis adapter: one pool per logical database, so
/// a slow command on one never blocks another.
pub struct RedisAdapter {
    pool: Arc<ConnPool>,
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
            db_label,
            role: database.role.clone(),
            stale: AtomicBool::new(false),
        })
    }

    /// Lease a connection, send one accepted command, shape the reply. The
    /// connection goes back to the pool only after a complete reply; if this
    /// future is dropped mid-command (timeout, agent disconnect) the lease
    /// drops with it and the connection is closed, never reused.
    async fn run(&self, command: Command, row_limit: u32) -> Result<ExecResult, ExecError> {
        let started = Instant::now();
        let mut lease = self
            .pool
            .lease()
            .await
            .map_err(|err| self.classify_connect(err))?;
        let sent = redis::cmd(command.name)
            .arg(&command.args)
            .query_async::<redis::Value>(lease.conn())
            .await;
        let reply = match sent {
            Ok(reply) => {
                lease.release().await;
                reply
            }
            Err(err) => {
                if connection_survives(&err) {
                    lease.release().await;
                }
                return Err(self.classify_command(err));
            }
        };
        let shaped = shape_reply(command.shape, reply, row_limit)?;
        Ok(ExecResult {
            columns: shaped.columns,
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
    /// over the lease *and* the command; on expiry the connection is
    /// discarded with the dropped future.
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        let command = rejector::validate_command(query.sql)
            .map_err(|err| ExecError::Forbidden(err.to_string()))?;
        let budget =
            Duration::from_millis(u64::from(effective_timeout_ms(query.statement_timeout_ms)));
        match tokio::time::timeout(budget, self.run(command, query.row_limit)).await {
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
