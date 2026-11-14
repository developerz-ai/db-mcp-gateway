//! `DbAdapter` trait — the contract every storage backend implements, plus
//! the timeout policy every impl must apply.
//!
//! [`super::pg::PgAdapter`] and [`super::mongo::MongoAdapter`] implement this
//! today; mysql (#59) slots in here without touching the tools layer: every
//! per-DB tool drives the registry and the registry returns the right
//! adapter. Engine-specific SQL (catalog lookups, sampling, `EXPLAIN`) lives
//! behind the trait, never in a tool.
//!
//! [`effective_timeout_ms`] lives here rather than in one impl because the
//! ceiling is a *gateway* policy, not a backend detail — an adapter that
//! computed its own would let a grant loosen past the ceiling and invert
//! most-restrictive-wins.
//!
//! Security note: `ExecError`'s `Display` never carries connection strings,
//! hostnames, passwords, or role names. The one variant that carries
//! server text, [`ExecError::Rejected`], is built only from a statement-level
//! database error (never a connect error) with the role name redacted. The
//! pg-side mapping is in `pg::error`; new adapters must preserve this
//! discipline.

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::config::ServerKind;

use super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, SampleQuery, SchemaQuery, TableStatsQuery,
};
use super::rejection::DbRejection;

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

/// Gateway-wide ceiling on the decoded size of one result — the byte
/// analogue of the row cap. A handful of wide `text`/`jsonb` rows can be
/// hundreds of MiB while staying under any row limit; past this budget the
/// adapter stops collecting and flags `truncated`, exactly as for the row
/// cap. Measured over the decoded JSON values (see `result_size`), not wire
/// bytes, because the decoded form is what the gateway holds in memory.
pub const MAX_RESULT_BYTES: usize = 32 * 1024 * 1024;

/// Extra slack on top of the DB-side timeout so the Tokio guard doesn't
/// preempt before the backend has a chance to surface its own cancel (which
/// carries the precise, typed error).
pub(super) const TOKIO_TIMEOUT_SLACK_MS: u64 = 500;

/// Effective per-query timeout in milliseconds. The grant value wins when
/// present (it may be more restrictive) but is clamped to the gateway
/// ceiling so it can only tighten, never loosen:
/// `effective = clamp(grant.unwrap_or(CEILING), 1, CEILING)`.
///
/// The floor of 1 is belt and braces: config and the admin API reject a zero
/// timeout, but Postgres reads `statement_timeout = 0` as *no limit*, so a
/// zero that slipped through would silently disable the DB-side cap.
pub(super) fn effective_timeout_ms(grant: Option<u32>) -> u32 {
    grant
        .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_MS)
        .clamp(1, DEFAULT_STATEMENT_TIMEOUT_MS)
}

/// Backend identifier — names the adapter in [`ExecError::NotImplemented`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AdapterKind {
    Postgres,
    Mongo,
}

/// Tabular result. `rows` is row-major; `columns` carries the names in their
/// stable left-to-right order. `truncated` means more rows were available
/// but the gateway stopped at `row_limit` or [`MAX_RESULT_BYTES`].
///
/// `rows_affected` is `Some` only for an
/// [`Access::ReadWrite`](super::sql_guard::Access::ReadWrite) query: the
/// number of rows the statement changed (or, under `dry_run`, would have
/// changed), which can exceed `rows.len()` when a `RETURNING` list was
/// truncated (the write itself is never cut short).
#[derive(Debug, Serialize)]
pub struct ExecResult {
    pub columns: Vec<String>,
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
    /// the code plus the server's primary message, role name redacted.
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
    /// `table_stats`, `db_activity` and `cancel_request`. The error carries the responsible
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
    /// Run a single query under the gateway-enforced timeout + row cap.
    /// See `ExecQuery` for the per-call inputs.
    async fn execute(&self, query: ExecQuery<'_>) -> Result<ExecResult, ExecError>;

    /// The schema, one row per column or per collection.
    ///
    /// - Postgres: every table in `query.schema` (or just `query.table`),
    ///   ordered by table then column position. Each row is exactly
    ///   `[schema, table, column, data_type, is_nullable]`, all strings;
    ///   `is_nullable` is `"YES"` / `"NO"`.
    /// - Mongo: every collection (or just `query.table`), ordered by name.
    ///   Each row is exactly `[database, collection, type, indexes]`: three
    ///   strings (`type` is `"collection"` / `"view"` / …) and a JSON array
    ///   of `{name, key, unique}`, empty for a view.
    async fn describe_schema(&self, query: SchemaQuery<'_>) -> Result<ExecResult, ExecError>;

    /// Up to `query.row_limit` rows of the table, with `truncated` set when
    /// the table holds more. Mongo answers one `document` column.
    async fn sample(&self, query: SampleQuery<'_>) -> Result<ExecResult, ExecError>;

    /// The statement's plan without running it: one row, one cell holding
    /// the plan as JSON — either parsed (`Value::Array` / `Value::Object`) or
    /// as JSON text (`Value::String`).
    async fn explain(&self, query: ExplainQuery<'_>) -> Result<ExecResult, ExecError>;

    /// Size, row estimate, dead tuples, last (auto)vacuum/analyze and
    /// per-index size + scan count for each table the read role may
    /// `SELECT`. Columns: `schema, table, total_bytes, table_bytes,
    /// index_bytes, row_estimate, live_rows, dead_rows, seq_scans,
    /// index_scans, last_vacuum, last_autovacuum, last_analyze,
    /// last_autoanalyze, indexes` — `indexes` a JSON array of
    /// `{name, bytes, scans}`.
    async fn table_stats(&self, query: TableStatsQuery<'_>) -> Result<ExecResult, ExecError>;

    /// The gateway's own non-idle backends on this database — read and
    /// write role both. Columns: `pid, request_id, pool, state,
    /// wait_event_type, wait_event, running_ms`; `request_id` is the gateway
    /// request that backend is running (a UUID string, `null` for a backend
    /// the gateway did not tag) and `pool` is `"read"` / `"write"`. No query
    /// text: the caller's own statements are in its audit rows.
    async fn db_activity(&self, query: ActivityQuery) -> Result<ExecResult, ExecError>;

    /// Cancel whatever statement the gateway is running for `request_id` on
    /// this database. `Ok(true)` when a backend was signalled, `Ok(false)`
    /// when none was running. Authorization — that `request_id` is the
    /// caller's own — is the tool's job; this only reaches backends of the
    /// gateway's own roles. The victim's call fails with
    /// [`ExecError::Cancelled`].
    async fn cancel_request(&self, request_id: Uuid) -> Result<bool, ExecError>;

    /// Whether the adapter saw the target reject its credentials. The
    /// registry replaces a stale adapter on the next lookup, so the new one
    /// re-resolves the password reference — rotation without a restart.
    fn is_stale(&self) -> bool;
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

    /// Postgres reads `statement_timeout = 0` as "no limit", so a zero grant
    /// must never reach the DB as zero.
    #[test]
    fn effective_timeout_never_zero() {
        assert_eq!(effective_timeout_ms(Some(0)), 1);
    }

    proptest::proptest! {
        /// For any grant: never zero (Postgres' "no limit"), never above the
        /// grant, never above the ceiling. The upper bound is floored at 1
        /// because a zero grant still runs with the 1 ms floor.
        #[test]
        fn effective_timeout_stays_within_grant_and_ceiling(
            grant in proptest::option::of(proptest::num::u32::ANY)
        ) {
            let effective = effective_timeout_ms(grant);
            let bound = grant
                .unwrap_or(u32::MAX)
                .clamp(1, DEFAULT_STATEMENT_TIMEOUT_MS);
            proptest::prop_assert!((1..=bound).contains(&effective));
        }
    }
}
