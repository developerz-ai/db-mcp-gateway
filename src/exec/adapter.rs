//! `DbAdapter` trait — the contract every storage backend implements, plus
//! the timeout policy every impl must apply.
//!
//! [`super::pg::PgAdapter`] and [`super::mongo::MongoAdapter`] implement this
//! today; mysql (#59) slots in here without touching the tools layer: every
//! per-DB tool drives the registry and the registry returns the right
//! adapter.
//!
//! [`effective_timeout_ms`] lives here rather than in one impl because the
//! ceiling is a *gateway* policy, not a backend detail — an adapter that
//! computed its own would let a grant loosen past the ceiling and invert
//! most-restrictive-wins.
//!
//! Security note: `ExecError`'s `Display` never carries connection strings,
//! hostnames, passwords, or SQLSTATE codes. The pg-side mapping is in
//! [`super::pg::classify`]; new adapters must preserve this discipline.

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::config::ServerKind;

/// Gateway-wide ceiling on a single query's wall-clock budget. When a grant
/// declines to set `statement_timeout_ms` (spec-06 "no constraint from this
/// side"), a query would otherwise run unbounded and pin a driver connection
/// indefinitely — a handful of those starve every other user of this
/// `(server, database)`. So the gateway always imposes this floor. A grant
/// may only *tighten* it (most-restrictive-wins): it can never raise the
/// budget above this ceiling. 30s is generous for an interactive read yet
/// short enough that a runaway query frees its connection promptly.
///
/// Every adapter applies this — the policy is the gateway's, not the
/// backend's, so it lives next to the trait rather than in one impl.
pub const DEFAULT_STATEMENT_TIMEOUT_MS: u32 = 30_000;

/// Extra slack on top of the DB-side timeout so the Tokio guard doesn't
/// preempt before the backend has a chance to surface its own cancel (which
/// carries the precise, typed error).
pub(super) const TOKIO_TIMEOUT_SLACK_MS: u64 = 500;

/// Effective per-query timeout in milliseconds. The grant value wins when
/// present (it may be more restrictive) but is clamped to the gateway
/// ceiling so it can only tighten, never loosen:
/// `effective = min(grant.unwrap_or(CEILING), CEILING)`.
pub(super) fn effective_timeout_ms(grant: Option<u32>) -> u32 {
    grant
        .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_MS)
        .min(DEFAULT_STATEMENT_TIMEOUT_MS)
}

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
/// 2. Bound EVERY call by [`effective_timeout_ms`] — never by the raw
///    `statement_timeout_ms`, which is `None` when the grant declines to cap
///    and may exceed the ceiling when it asks for more. Push it to the DB if
///    the backend supports it (`SET LOCAL statement_timeout` / `maxTimeMS`)
///    *and* wrap the whole call in a `tokio::time::timeout`, so a backend
///    that ignores the DB-side cap still can't pin a connection.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_timeout_clamps_and_defaults() {
        // No grant constraint → gateway ceiling, never unbounded.
        assert_eq!(effective_timeout_ms(None), DEFAULT_STATEMENT_TIMEOUT_MS);
        assert_eq!(effective_timeout_ms(None), 30_000);
        // A tighter grant wins (most-restrictive-wins).
        assert_eq!(effective_timeout_ms(Some(5_000)), 5_000);
        // A looser grant is clamped down to the ceiling — it can only tighten.
        assert_eq!(effective_timeout_ms(Some(60_000)), 30_000);
        assert_eq!(effective_timeout_ms(Some(3_600_000)), 30_000);
    }
}
