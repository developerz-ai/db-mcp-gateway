//! `DbAdapter` trait — the contract every storage backend implements.
//!
//! Only [`super::pg::PgAdapter`] implements this today. Mongo (#57) and
//! mysql (#59) slot in here without touching the tools layer: every per-DB
//! tool drives the registry and the registry returns the right adapter.
//!
//! Security note: `ExecError`'s `Display` never carries connection strings,
//! hostnames, passwords, or SQLSTATE codes. The pg-side mapping is in
//! [`super::pg::classify`]; new adapters must preserve this discipline.

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::config::ServerKind;

/// Backend identifier — used for metrics tagging and per-adapter dispatch.
/// More variants land as `PgAdapter`'s siblings arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterKind {
    Postgres,
    Mongo,
}

/// A single query against the adapter. `binds` are positional text values
/// applied in order — `$1`, `$2`, … for pg; future adapters define their own
/// placeholder convention. `binds = &[]` for queries with no parameters.
#[derive(Debug)]
pub struct ExecQuery<'a> {
    pub sql: &'a str,
    pub binds: &'a [&'a str],
    pub statement_timeout_ms: Option<u32>,
    pub row_limit: u32,
}

/// Tabular result. `rows` is row-major; `columns` carries the names in their
/// stable left-to-right order. `truncated` means more rows were available
/// but the gateway stopped at `row_limit`.
#[derive(Debug, Serialize)]
pub struct ExecResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
    pub elapsed_ms: u64,
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

    #[error("query exceeded the configured statement_timeout")]
    Timeout,

    #[error("SQL rejected by the DB")]
    Sql,

    /// Gateway-side policy rejection — defense-in-depth on top of the
    /// least-privilege DB role. Today this fires only from
    /// `MongoAdapter::execute`, which runs the read-only rejector before
    /// dispatching the command (#57). The pg path performs the same check
    /// in the tool layer (`sql_guard::is_read_only` → `forbidden_sql`)
    /// before ever calling `execute`, so this variant exists for adapters
    /// whose policy check is intrinsic to dispatch. Tools map it to the
    /// `forbidden_sql` outcome code per spec 03 / 07.
    ///
    /// The carried string is the operator-facing rejection reason — the
    /// `RejectReason::Display` rendering — and is safe to surface (no
    /// command values, no credentials). See `mongo::rejector::RejectReason`.
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

    /// The adapter is registered but the requested operation is not yet
    /// implemented. Today this fires only on `MongoAdapter::execute` — the
    /// scaffold from #57 runs the read-only rejector but defers actual
    /// query execution to #58. The error carries the responsible
    /// `AdapterKind` and the operation name so operators see exactly which
    /// gap was hit.
    #[error("adapter `{adapter:?}` has not implemented `{op}` yet")]
    NotImplemented {
        adapter: AdapterKind,
        op: &'static str,
    },
}

/// Per-`(server, database)` storage adapter. One instance per logical DB —
/// the registry hands out `Arc<dyn DbAdapter>` to tools.
///
/// Object-safe via `#[async_trait]`. Implementations must:
///
/// 1. Never let credentials leak into `ExecError::Display`, tracing fields,
///    or panic payloads (CLAUDE.md non-negotiable #1).
/// 2. Honor `statement_timeout_ms` *at the DB* if the backend supports it,
///    so a single misuse can't outlive its tx. Future-drop is the secondary
///    cancellation chain — see `PgAdapter::execute` for the pg pattern.
/// 3. Surface row truncation via `ExecResult.truncated` instead of returning
///    more than `row_limit` rows.
#[async_trait]
pub trait DbAdapter: Send + Sync + std::fmt::Debug {
    /// Backend identifier — used for `metrics!` tagging and per-adapter
    /// dispatch from generic tool code.
    fn kind(&self) -> AdapterKind;

    /// Run a single query under the gateway-enforced timeout + row cap.
    /// See `ExecQuery` for the per-call inputs.
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError>;

    /// Cheap liveness probe — `SELECT 1` (or backend equivalent). Used by
    /// `/readyz` to confirm the adapter's pool can still acquire a connection
    /// without consulting the underlying DB's query planner.
    async fn health(&self) -> Result<(), ExecError>;
}
