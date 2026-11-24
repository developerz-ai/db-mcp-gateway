//! The adapter contract's value types: which backend, what a call
//! returned, and how it failed.

use serde::Serialize;
use serde_json::Value;

use crate::config::ServerKind;

use super::super::rejection::DbRejection;

/// Backend identifier — names the adapter in [`ExecError::NotImplemented`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterKind {
    Postgres,
    Mongo,
    Redis,
}

/// Tabular result. `rows` is row-major; `columns` carries the names in their
/// stable left-to-right order. `truncated` means more rows were available
/// but the gateway stopped at `row_limit` or [`MAX_RESULT_BYTES`](crate::exec::MAX_RESULT_BYTES).
///
/// `rows_affected` is `Some` only for an
/// [`Access::ReadWrite`](crate::exec::sql_guard::Access::ReadWrite) query: the
/// number of rows the statement changed (or, under `dry_run`, would have
/// changed), which can exceed `rows.len()` when a `RETURNING` list was
/// truncated (the write itself is never cut short).
///
/// `column_types` names each column's type, in the same order as
/// `columns`; empty when the backend has no type info (Mongo, Redis).
#[derive(Debug, Default, Serialize)]
pub struct ExecResult {
    pub columns: Vec<String>,
    pub column_types: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
    pub elapsed_ms: u64,
    pub rows_affected: Option<u64>,
}

/// Typed execution errors. `Display` carries no secrets, hostnames, or
/// connection strings; details for operators live in `tracing` events and
/// the chained `source()`. Tools map these to stable tool-error codes
/// — see `outcome_from_exec_error` in each tool.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("connection to target DB failed")]
    Connection,

    #[error("DB unavailable")]
    Unavailable,

    /// `COMMIT` of a write failed without a definitive answer from the
    /// server (lost connection, protocol error): the write may or may not
    /// have committed. Client-facing it is still `unavailable`; tools must
    /// say the outcome is unknown, never that nothing changed.
    #[error("write outcome unknown: the commit did not complete")]
    CommitIndeterminate,

    #[error("query exceeded the configured statement_timeout")]
    Timeout,

    /// The statement was cancelled before its budget ran out — by the
    /// `cancel_query` tool (`DbAdapter::cancel_request`) or an operator's
    /// `pg_cancel_backend`. Tools map it to the `cancelled` outcome.
    #[error("query was cancelled")]
    Cancelled,

    /// A write was requested on a database with no `write_role`. Config
    /// validation refuses a YAML `query_write` grant on such a database, so
    /// this is reached only through a dynamic (admin API) grant. Tools map
    /// it to `forbidden`. Names no role.
    #[error("this database has no write role configured")]
    WriteNotConfigured,

    /// The DB refused the statement and the reason is opaque (a protocol or
    /// decode failure, or a non-Postgres backend's command error).
    #[error("SQL rejected by the DB")]
    Sql,

    /// The DB refused the statement with a SQLSTATE the agent can act on:
    /// the code plus gateway wording keyed by it (no server text).
    /// Tools map it by [`DbRejection::kind`].
    #[error("SQL rejected by the DB: {0}")]
    Rejected(DbRejection),

    /// The target answered, but with a value the gateway could not decode
    /// (a Mongo reply missing its documented field, an undecodable BSON
    /// document). Never papered over with a fabricated `null`.
    #[error("target DB returned a response the gateway could not decode")]
    Decode,

    /// Gateway-side policy rejection — defense-in-depth on top of the
    /// least-privilege DB role. Fires from `MongoAdapter::execute`, which
    /// runs the read-only rejector before dispatching the command (#57), and
    /// from the pg `explain` when `analyze` is asked of a write. The pg SQL
    /// guard itself runs in the tool layer (`sql_guard` → `forbidden_sql`)
    /// before `execute` is ever called. Tools map this variant to the
    /// `forbidden_sql` outcome code per spec 03 / 07.
    ///
    /// The carried string is the operator-facing rejection reason (for
    /// Mongo, the `RejectReason::Display` rendering) and is safe to surface
    /// (no command values, no credentials). See `mongo::rejector::RejectReason`.
    #[error("operation rejected by gateway policy: {0}")]
    Forbidden(String),

    #[error("password reference `{kind}:{reference}` could not be resolved")]
    PasswordUnresolved {
        kind: &'static str,
        reference: String,
    },

    /// The configured `server.kind` has no adapter wired in yet. Today this
    /// covers `mysql` / `mssql`. The error carries the `ServerKind` so
    /// operators can read the boot-time log and the corresponding YAML
    /// stanza without a second lookup.
    #[error("no adapter is registered for server kind `{0:?}`")]
    UnsupportedAdapter(ServerKind),

    /// The adapter is registered but does not support the requested
    /// operation. Today this fires on `MongoAdapter`'s `explain`,
    /// `table_stats`, `db_activity` and `cancel_request`, and on every
    /// `RedisAdapter` operation but `execute`. The error carries the responsible
    /// `AdapterKind` and the operation name so operators see exactly which
    /// gap was hit.
    #[error("adapter `{adapter:?}` has not implemented `{op}` yet")]
    NotImplemented {
        adapter: AdapterKind,
        op: &'static str,
    },
}
