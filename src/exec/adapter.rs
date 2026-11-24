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

use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use super::query::{
    ActivityQuery, ExecQuery, ExplainQuery, QueryParam, SampleQuery, SchemaQuery, TableStatsQuery,
};

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
/// cap. Measured over the decoded JSON values, node by node (see `budget`):
/// that is what the gateway holds, and it can be several times the wire form.
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
pub(crate) fn effective_timeout_ms(grant: Option<u32>) -> u32 {
    grant
        .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_MS)
        .clamp(1, DEFAULT_STATEMENT_TIMEOUT_MS)
}

/// Who a tool call runs for, as the exec layer sees it: the key under which
/// each adapter counts that caller's share of a connection pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caller(Arc<str>);

impl Caller {
    pub fn new(subject: &str) -> Self {
        Self(Arc::from(subject))
    }
}

tokio::task_local! {
    static CALLER: Caller;
}

/// Run `call` on behalf of `caller`: every target connection an adapter
/// takes inside it counts against that caller's share of the pool. Scoped
/// once, where a tool call is dispatched, so a tool cannot forget to name
/// its caller. Work outside any scope is the gateway's own and is not
/// counted.
pub async fn for_caller<F: Future>(caller: Caller, call: F) -> F::Output {
    CALLER.scope(caller, call).await
}

/// The caller the current task runs for, if any.
pub(super) fn current_caller() -> Option<Caller> {
    CALLER.try_with(Clone::clone).ok()
}

/// A backend without positional placeholders stops here; the tools refuse
/// params for it first, as `invalid_arguments`.
fn refuse_params(params: &[QueryParam]) -> Result<(), ExecError> {
    match params {
        [] => Ok(()),
        _ => Err(ExecError::Forbidden(
            "this backend takes no params".to_owned(),
        )),
    }
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

    /// [`Self::execute`] with `params` bound, in order, to the statement's
    /// positional placeholders. Only Postgres has them; the default refuses
    /// any rather than run the statement without them.
    async fn execute_with_params(
        &self,
        query: ExecQuery<'_>,
        params: &[QueryParam],
    ) -> Result<ExecResult, ExecError> {
        refuse_params(params)?;
        self.execute(query).await
    }

    /// The catalog at `query.detail` (row shapes on
    /// [`SchemaDetail`](super::query::SchemaDetail)), over `query.schema`
    /// (every schema the read role may use when `None`; Mongo has none),
    /// narrowed by `query.table` and `query.search`; ordered by name.
    async fn describe_schema(&self, query: SchemaQuery<'_>) -> Result<ExecResult, ExecError>;

    /// Up to `query.row_limit` rows of the table, with `truncated` set when
    /// the table holds more. Mongo answers one `document` column.
    async fn sample(&self, query: SampleQuery<'_>) -> Result<ExecResult, ExecError>;

    /// The statement's plan without running it: one row, one cell holding
    /// the plan as JSON — either parsed (`Value::Array` / `Value::Object`) or
    /// as JSON text (`Value::String`).
    async fn explain(&self, query: ExplainQuery<'_>) -> Result<ExecResult, ExecError>;

    /// [`Self::explain`] with `params` bound, as in [`Self::execute_with_params`].
    async fn explain_with_params(
        &self,
        query: ExplainQuery<'_>,
        params: &[QueryParam],
    ) -> Result<ExecResult, ExecError> {
        refuse_params(params)?;
        self.explain(query).await
    }

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

mod types;
pub use types::{AdapterKind, ExecError, ExecResult};

#[cfg(test)]
mod tests;
