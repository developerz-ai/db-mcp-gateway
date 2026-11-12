//! MongoDB target adapter — read-only enforcement + command execution.
//!
//! Wire-shape: [`MongoAdapter`] implements [`super::DbAdapter`] and is
//! dispatched to by [`super::AdapterRegistry`] when `server.kind` is
//! [`crate::config::ServerKind::Mongo`]. Tools never see the concrete
//! type — they only see `Arc<dyn DbAdapter>` from the registry, identical
//! to the pg path.
//!
//! `execute` runs the [`rejector`] first; only an accepted read command
//! reaches the driver, and it reaches it under the gateway's always-present
//! time budget ([`super::adapter::effective_timeout_ms`]) — see
//! [`MongoAdapter::execute`] for the timeout / cancellation contract.
//!
//! Security-required (CLAUDE.md). The connection password is *never*
//! embedded in `Display` for any error or in any tracing field, identical
//! to the pg adapter discipline (`PgAdapter::Debug` redaction pattern).
//! Credentials are passed to the driver as structured `Credential` fields
//! (not concatenated into a URI), so no encoding bug can turn a
//! `:`-bearing password into URI structure. See [`MongoAdapter::open`].

mod bson_json;
mod cancel;
mod catalog;
mod dispatch;
pub mod rejector;
#[cfg(test)]
mod tests;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use mongodb::Client;
use mongodb::options::{ClientOptions, Credential, ServerAddress, Tls as MongoTls, TlsOptions};
use secrecy::ExposeSecret;

use crate::audit::drain::DetachedTasks;
use crate::config::{Database, Server, Tls};

use uuid::Uuid;

use super::adapter::{
    AdapterKind, DbAdapter, ExecError, ExecResult, TOKIO_TIMEOUT_SLACK_MS, effective_timeout_ms,
};
use super::pg::resolve_password;
use super::pool_sizing::PoolSizing;
use super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};

/// Bound on server selection and on opening one connection — the Mongo
/// analogue of the pg pool's acquire timeout. Without it the driver waits
/// 30 s for an unreachable host.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-`(server, database)` mongo adapter. Wraps a `mongodb::Client`; one
/// instance per logical DB so a slow query on DB A can never block DB B.
pub struct MongoAdapter {
    client: Client,
    /// Composite label for metrics tagging — bounded cardinality, supplied
    /// from YAML config rather than user input.
    db_label: String,
    /// Default database the adapter dispatches commands against — derived
    /// from the YAML `databases[].name` at construction. The mongo wire
    /// protocol needs the database explicitly on every `run_command`;
    /// stashing it here keeps the per-request dispatch lookup-free.
    database_name: String,
    /// Set when the server rejected the credentials; the registry then
    /// replaces this adapter so the password is resolved again.
    stale: AtomicBool,
    /// Tracks drop-guard kills so a shutdown drain waits for them.
    detached: DetachedTasks,
}

impl std::fmt::Debug for MongoAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `mongodb::Client`'s `Debug` would render the parsed options
        // including credentials. Never let that leak — print structural
        // info only. Same posture as `PgAdapter::Debug`.
        f.debug_struct("MongoAdapter")
            .field("db", &self.db_label)
            .finish()
    }
}

impl MongoAdapter {
    /// Open a fresh mongo client for `(server, database)`. Lazy in the
    /// network sense: building `ClientOptions` doesn't open a TCP
    /// connection; the first operation does. Same posture as
    /// `PgAdapter::open` — misconfiguration surfaces on first use, not at
    /// boot.
    pub async fn open(
        server: &Server,
        database: &Database,
        sizing: PoolSizing,
        detached: DetachedTasks,
    ) -> Result<Self, ExecError> {
        let password = resolve_password(&database.password).await?;

        // Structured credentials avoid any URI-string assembly: a
        // password containing `:` or `@` can't accidentally rewrite the
        // host segment because the driver receives username/password as
        // separate fields. Same posture as sqlx's `PgConnectOptions`.
        // `authSource` controls which database mongo verifies the role
        // against. Operators pick this per their deployment:
        //   - `None` (default) → fall back to `database.name`: the
        //     least-privilege per-db user pattern spec 12 §237 calls out.
        //   - `Some("admin")` → cross-db user (mongo's container bootstrap
        //     pattern, common in dev / quickstart setups).
        let credential = Credential::builder()
            .username(database.role.clone())
            // The driver boundary: expose the plaintext only here, where mongo's
            // `Credential` takes ownership of its own `String` copy.
            .password(password.expose_secret().to_owned())
            .source(Some(
                database
                    .auth_database
                    .clone()
                    .unwrap_or_else(|| database.name.clone()),
            ))
            .build();

        let mut options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: server.host.clone(),
                port: Some(server.port),
            }])
            .credential(credential)
            .default_database(database.name.clone())
            .build();
        // The driver verifies chain and hostname by default, so `required`
        // and `verify_full` are the same here; Postgres `required` is not.
        options.tls = match server.tls {
            Tls::Required | Tls::VerifyFull => Some(MongoTls::Enabled(
                TlsOptions::builder()
                    .ca_file_path(server.tls_ca_file.clone())
                    .build(),
            )),
            Tls::Insecure => None,
        };
        options.max_pool_size = Some(sizing.max_connections);
        options.min_pool_size = Some(sizing.min_connections);
        options.max_idle_time = Some(sizing.idle_timeout);
        options.server_selection_timeout = Some(CONNECT_TIMEOUT);
        options.connect_timeout = Some(CONNECT_TIMEOUT);

        let client = Client::with_options(options).map_err(|_| ExecError::Connection)?;
        let db_label = format!("{}/{}", server.name, database.name);
        let database_name = database.name.clone();
        Ok(Self {
            client,
            db_label,
            database_name,
            stale: AtomicBool::new(false),
            detached,
        })
    }
}

#[async_trait]
impl DbAdapter for MongoAdapter {
    /// Read-only enforcement first; on accept, dispatch the parsed BSON
    /// command to the mongo driver under the gateway's time budget.
    ///
    /// A rejected command maps to [`ExecError::Forbidden`] (→ tool code
    /// `forbidden_sql`), matching the pg path's `sql_guard::is_read_only`
    /// posture. Per spec 03, this is a policy denial, not a syntax error.
    /// Mongo targets are read-only whatever `query.access` says: a
    /// `query_write` grant on a Mongo database still hits the rejector.
    ///
    /// **Timeout** — identical semantics to `PgAdapter::execute`. The budget
    /// is [`effective_timeout_ms`]: always present, and clamped so a grant
    /// can only tighten it. It is applied twice, because neither half is
    /// sufficient alone:
    ///
    /// - `maxTimeMS` on the command, so mongo kills the operation
    ///   server-side and we get the precise `MaxTimeMSExpired` (code 50) →
    ///   [`ExecError::Timeout`] mapping.
    /// - A `tokio::time::timeout` around the whole dispatch *including the
    ///   cursor drain*, because `maxTimeMS` does not reliably reach the
    ///   `getMore` round-trips that drain the rest of the cursor (mongo
    ///   carries an aggregation cursor's deadline into `getMore`; a `find`
    ///   cursor's is not covered), so a large result set would otherwise
    ///   blow straight through the budget.
    ///
    /// **Cancellation** — best-effort server-side kill of the *initial*
    /// command phase via `cancel::KillOpOnDrop` (#141), the mongo analogue
    /// of the pg path's `pg_cancel_backend` drop guard. Every command is
    /// stamped with a unique `comment` marker before dispatch; if the
    /// future is dropped mid-operation (agent disconnect), the guard's
    /// `Drop` spawns a detached `currentOp` lookup by that marker followed
    /// by `killOp` on every matching `opid` (a `mongos` fan-out surfaces
    /// one entry per shard). A disconnect during the *cursor drain* is
    /// covered by the driver's own `killCursors` on `Cursor::drop`, not by
    /// this guard — the marker rides on the initial `find` / `aggregate`
    /// but each `getMore` round-trip is a fresh operation with no marker
    /// to find. Three things keep even the initial-phase kill short of a
    /// guarantee (see `cancel` module docs for the full rationale):
    /// `killOp` and `currentOp` (with `$ownOps: false`) both require
    /// cluster-admin privileges the least-privilege mongo role doesn't
    /// have by default, the `currentOp` lookup can race a very short-lived
    /// operation's own registration, and only the initial command is
    /// targeted. Either way `maxTimeMS` remains the hard backstop. (The
    /// `outcome: cancelled` audit row is unaffected: it is written by the
    /// backend-agnostic drop guard in `tools::audit_dispatch`.)
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError> {
        rejector::validate_command(query.sql)
            .map_err(|err| ExecError::Forbidden(err.to_string()))?;

        let effective_ms = effective_timeout_ms(query.statement_timeout_ms);
        let budget = Duration::from_millis(u64::from(effective_ms) + TOKIO_TIMEOUT_SLACK_MS);
        match tokio::time::timeout(budget, self.dispatch(&query, effective_ms)).await {
            Ok(result) => result,
            Err(_elapsed) => Err(ExecError::Timeout),
        }
    }

    async fn describe_schema(&self, query: SchemaQuery<'_>) -> Result<ExecResult, ExecError> {
        self.describe(query).await
    }

    async fn sample(&self, query: SampleQuery<'_>) -> Result<ExecResult, ExecError> {
        self.sample_collection(query).await
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
        adapter: AdapterKind::Mongo,
        op,
    }
}
