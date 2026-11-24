//! Per-query transaction orchestration: open the transaction in the caller's
//! access mode, tag it, arm the cancel guard, apply the DB-side
//! `statement_timeout`, stream rows up to the budget, then commit, roll back
//! (`dry_run`) or cancel.

use std::time::{Duration, Instant};

use sqlx::{Connection, Executor, PgConnection, PgPool};
use tokio::sync::Semaphore;

use crate::audit::drain::DetachedTasks;

use super::super::adapter::{ExecError, ExecResult, effective_timeout_ms};
use super::super::query::{ExecQuery, QueryParam};
use super::super::sql_guard::Access;
use super::cancel::{Backend, BackendTag, CancelOnDrop};
use super::describe::describe_read;
use super::error::{Origin, classify, classify_commit};
use super::stream::stream_rows;
use super::truncate::cancel_and_rollback;

/// What one run needs besides the query: where cancels go and run, where its
/// errors are logged from (and the role name to redact from server
/// messages), and the adapter's large-row gate.
pub(super) struct RunCtx<'a> {
    pub(super) cancel_pool: &'a PgPool,
    pub(super) origin: Origin<'a>,
    pub(super) detached: &'a DetachedTasks,
    pub(super) large_rows: &'a Semaphore,
}

/// Run `query` in its own transaction. A read is described first (see
/// [`describe`](super::describe)): when a column's type has no binary form
/// the driver can take, the text-cast statement runs instead of it — once.
pub(super) async fn run_query(
    conn: &mut PgConnection,
    ctx: &RunCtx<'_>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
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
        let described = match query.access {
            Access::ReadOnly => Some(describe_read(&mut tx, query, params, origin).await?),
            Access::ReadWrite => None,
        };
        let sql = described
            .as_ref()
            .and_then(|described| described.recast.as_deref())
            .unwrap_or(query.sql);
        let to_run = ExecQuery { sql, ..*query };
        let collected = stream_rows(
            &mut tx,
            &to_run,
            params,
            origin,
            ctx.large_rows,
            money_digits,
        )
        .await?;
        // A read's columns come from its description: a zero-row read has
        // no row to name them (#136).
        let (columns, column_types) = match described {
            Some(described) => (described.columns, described.column_types),
            None => (collected.columns, collected.column_types),
        };
        if query.access == Access::ReadOnly && collected.truncated {
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
            column_types,
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
