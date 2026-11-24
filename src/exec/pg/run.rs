//! Per-query transaction orchestration: open the transaction in the caller's
//! access mode, tag it, arm the cancel guard, apply the DB-side
//! `statement_timeout`, stream rows up to the budget, then commit, roll back
//! (`dry_run`) or cancel.

use std::time::{Duration, Instant};

use sqlx::{Column, Connection, Executor, PgConnection, PgPool, Postgres, SqlSafeStr, Transaction};
use tokio::sync::Semaphore;

use crate::audit::drain::DetachedTasks;

use super::super::adapter::{ExecError, ExecResult, effective_timeout_ms};
use super::super::query::ExecQuery;
use super::super::sql_guard::Access;
use super::cancel::{Backend, BackendTag, CancelOnDrop};
use super::error::{Origin, classify, classify_commit};
use super::recast;
use super::stream::stream_rows;
use super::truncate::cancel_and_rollback;

/// Longest the zero-row column lookup may take. It is a parse, not an
/// execution; this only bounds a target that stalls on it.
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(1);

/// What one run needs besides the query: where cancels go and run, where its
/// errors are logged from (and the role name to redact from server
/// messages), and the adapter's large-row gate.
pub(super) struct RunCtx<'a> {
    pub(super) cancel_pool: &'a PgPool,
    pub(super) origin: Origin<'a>,
    pub(super) detached: &'a DetachedTasks,
    pub(super) large_rows: &'a Semaphore,
}

/// Run `query` in its own transaction. A read the target refused because a
/// column's type has no binary form is run once more with those columns
/// cast to text (see [`recast`]); when that is not possible, or the target
/// refuses the second statement too, the first refusal is the answer. The
/// second attempt is the one that ran, so its timeout, cancel or lost
/// connection is the answer.
pub(super) async fn run_query(
    conn: &mut PgConnection,
    ctx: &RunCtx<'_>,
    query: &ExecQuery<'_>,
) -> Result<ExecResult, ExecError> {
    let refused = match run_query_inner(conn, ctx, query).await {
        Err(err) if recast::may_apply(&err, query) => err,
        done => return done,
    };
    let Some(sql) = recast::text_cast_sql(conn, ctx, query).await else {
        return Err(refused);
    };
    let recast = ExecQuery {
        sql: &sql,
        ..*query
    };
    match run_query_inner(conn, ctx, &recast).await {
        Err(ExecError::Sql | ExecError::Rejected(_)) => Err(refused),
        done => done,
    }
}

async fn run_query_inner(
    conn: &mut PgConnection,
    ctx: &RunCtx<'_>,
    query: &ExecQuery<'_>,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let origin = &ctx.origin;
    let mut tx = conn.begin().await.map_err(|e| classify(e, origin, ""))?;

    // One round trip, before any other statement: `SET TRANSACTION` must
    // precede the transaction's first query. The read-only transaction is the
    // database's own enforcement of a read grant — the SQL guard is the
    // second layer, not the only one. Every interpolated value is a number
    // or a `BackendTag`, which contains no quote. The lexing pin is repeated
    // here because behind a transaction-mode pooler the session-level pin
    // may have landed on a different server connection than this one.
    let tag = BackendTag::for_request(query.request_id);
    let ms = effective_timeout_ms(query.statement_timeout_ms);
    let mode = match query.access {
        Access::ReadOnly => "READ ONLY",
        Access::ReadWrite => "READ WRITE",
    };
    let setup = format!(
        "SET TRANSACTION {mode}; SET LOCAL statement_timeout = {ms}; \
         SET LOCAL application_name = '{}'; \
         SET LOCAL standard_conforming_strings = on",
        tag.as_str()
    );
    tx.execute(sqlx::AssertSqlSafe(setup))
        .await
        .map_err(|e| classify(e, origin, ""))?;

    // Capture this connection's backend so a drop (agent disconnect) can
    // cancel the exact backend running our query — dropping `tx` alone won't
    // stop it. The guard holds the *cancel* pool so the cancel can always
    // acquire, even when every connection in the query pool is pinned.
    // Unnamed, like every statement on a query connection: nothing is left
    // prepared on it for `reset_on_release` to close. The same round trip
    // asks how many of a `money` value's digits are its fraction: the wire
    // form is a bare count of minor units, and `lc_monetary` says the rest.
    let (pid, money_digits): (i32, i32) =
        sqlx::query_as("SELECT pg_backend_pid(), scale(1::money::numeric)")
            .persistent(false)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| classify(e, origin, ""))?;
    // Postgres itself falls back to 2 outside 0..=10.
    let money_digits = u8::try_from(money_digits)
        .ok()
        .filter(|d| *d <= 10)
        .unwrap_or(2);
    let backend = Backend { pid, tag };
    let mut cancel = CancelOnDrop::armed(
        ctx.cancel_pool.clone(),
        backend.clone(),
        ctx.detached.clone(),
    );

    // By the time this block resolves — Ok OR Err — the backend has stopped
    // executing our query, so we disarm before returning. The guard stays
    // armed ONLY if this future is dropped while awaiting (agent disconnect
    // / outer `tokio::time::timeout`): the one case where the backend is
    // still running and must be cancelled.
    let result = async {
        let collected = stream_rows(&mut tx, query, origin, ctx.large_rows, money_digits).await?;
        let mut columns = collected.columns;
        // Reads only. Inside a write's transaction a failed lookup would
        // abort it, and the `COMMIT` that follows would then roll the write
        // back while reporting success.
        let mut in_step = true;
        if columns.is_empty() && query.access == Access::ReadOnly {
            let left = Duration::from_millis(u64::from(ms)).saturating_sub(started.elapsed());
            match describe_columns(&mut tx, query.sql, left.min(DESCRIBE_TIMEOUT)).await {
                Some(described) => columns = described,
                None => in_step = false,
            }
        }
        if !in_step {
            // The lookup is still in flight on this connection and the read
            // is already answered: waiting for the connection again could
            // only turn that answer into a timeout. Dropping the transaction
            // rolls it back when the connection is released.
            drop(tx);
        } else if query.access == Access::ReadOnly && collected.truncated {
            cancel_and_rollback(tx, ctx.cancel_pool, &backend).await;
        } else if query.dry_run {
            // The statement ran to completion; its effect is discarded. A
            // failed rollback is an error: the change must not be reported
            // as undone unless it was.
            tx.rollback()
                .await
                .map_err(|e| classify(e, origin, query.sql))?;
        } else {
            // A write is never cut short: the stream was drained, so the
            // statement completed, and it commits whether or not the
            // `RETURNING` rows were truncated. A failed commit is an error —
            // never success after a rollback.
            tx.commit()
                .await
                .map_err(|e| classify_commit(e, query.access, origin, query.sql))?;
        }
        let rows_affected = (query.access == Access::ReadWrite).then_some(collected.rows_affected);
        Ok(ExecResult {
            columns,
            rows: collected.rows,
            truncated: collected.truncated,
            elapsed_ms: started.elapsed().as_millis() as u64,
            rows_affected,
        })
    }
    .await;
    cancel.disarm();
    result.map_err(|err| cancelled_before_budget(err, started.elapsed(), ms))
}

/// `statement_timeout` and `pg_cancel_backend` both raise SQLSTATE `57014`.
/// The timeout cannot fire before its budget, so a `57014` earlier than that
/// is a cancel: the `cancel_query` tool, or an operator.
fn cancelled_before_budget(err: ExecError, elapsed: Duration, budget_ms: u32) -> ExecError {
    match err {
        ExecError::Timeout if elapsed < Duration::from_millis(u64::from(budget_ms)) => {
            ExecError::Cancelled
        }
        other => other,
    }
}

/// Column names for a zero-row read. Without them the caller cannot tell
/// "your filter matched nothing" from "that table has no such columns"
/// (#136). Parse/Describe only — the statement does not run again. The
/// driver can only describe through a named statement; `reset_on_release`
/// closes it before the connection serves anyone else.
///
/// Best-effort on purpose: the read already succeeded, so a failure here
/// answers no columns, never an error. `None` means `budget` ran out with
/// the lookup still in flight on the connection.
async fn describe_columns(
    tx: &mut Transaction<'_, Postgres>,
    sql: &str,
    budget: Duration,
) -> Option<Vec<String>> {
    let described = tokio::time::timeout(
        budget,
        (&mut **tx).describe(sqlx::AssertSqlSafe(sql).into_sql_str()),
    )
    .await
    .ok()?;
    Some(match described {
        Ok(described) => described
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect(),
        Err(_) => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_early_query_canceled_is_a_cancel_not_a_timeout() {
        let early = cancelled_before_budget(ExecError::Timeout, Duration::from_millis(10), 1_000);
        assert!(matches!(early, ExecError::Cancelled), "{early:?}");
        let late = cancelled_before_budget(ExecError::Timeout, Duration::from_millis(1_000), 1_000);
        assert!(matches!(late, ExecError::Timeout), "{late:?}");
        let other = cancelled_before_budget(ExecError::Sql, Duration::ZERO, 1_000);
        assert!(matches!(other, ExecError::Sql), "{other:?}");
    }
}
