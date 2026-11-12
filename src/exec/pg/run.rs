//! Per-query transaction orchestration: open the transaction in the caller's
//! access mode, tag it, arm the cancel guard, apply the DB-side
//! `statement_timeout`, stream rows up to the budget, then commit or cancel.

use std::time::Instant;

use futures::StreamExt;
use serde_json::Value;
use sqlx::{Column, Connection, Either, Executor, PgConnection, PgPool, Postgres, Transaction};

use crate::audit::drain::DetachedTasks;

use super::super::adapter::{ExecError, ExecQuery, ExecResult, effective_timeout_ms};
use super::super::budget::ResultBudget;
use super::super::sql_guard::Access;
use super::cancel::{Backend, BackendTag, CancelOnDrop};
use super::decode::{decode_row, decoders};
use super::error::classify;
use super::truncate::cancel_and_rollback;

/// What one run needs besides the query: where cancels go and run, and the
/// role name to redact from server messages.
pub(super) struct RunCtx<'a> {
    pub(super) cancel_pool: &'a PgPool,
    pub(super) role: &'a str,
    pub(super) detached: &'a DetachedTasks,
}

/// Rows collected so far plus what the stream said about the statement.
struct Collected {
    columns: Vec<String>,
    rows: Vec<Vec<Value>>,
    truncated: bool,
    rows_affected: u64,
}

pub(super) async fn run_query_inner(
    conn: &mut PgConnection,
    ctx: &RunCtx<'_>,
    query: &ExecQuery<'_>,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let role = ctx.role;
    let mut tx = conn.begin().await.map_err(|e| classify(e, role))?;

    // One round trip, before any other statement: `SET TRANSACTION` must
    // precede the transaction's first query. The read-only transaction is the
    // database's own enforcement of a read grant — the SQL guard is the
    // second layer, not the only one. Every interpolated value is a number
    // or a `BackendTag`, which contains no quote.
    let tag = BackendTag::new();
    let ms = effective_timeout_ms(query.statement_timeout_ms);
    let mode = match query.access {
        Access::ReadOnly => "READ ONLY",
        Access::ReadWrite => "READ WRITE",
    };
    let setup = format!(
        "SET TRANSACTION {mode}; SET LOCAL statement_timeout = {ms}; \
         SET LOCAL application_name = '{}'",
        tag.as_str()
    );
    tx.execute(setup.as_str())
        .await
        .map_err(|e| classify(e, role))?;

    // Capture this connection's backend so a drop (agent disconnect) can
    // cancel the exact backend running our query — dropping `tx` alone won't
    // stop it. The guard holds the *cancel* pool so the cancel can always
    // acquire, even when every connection in the query pool is pinned.
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| classify(e, role))?;
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
        let collected = stream_rows(&mut tx, query, role).await?;
        let columns = if collected.columns.is_empty() {
            describe_columns(&mut tx, query.sql).await
        } else {
            collected.columns
        };
        let rows_affected = match query.access {
            Access::ReadOnly if collected.truncated => {
                cancel_and_rollback(tx, ctx.cancel_pool, &backend).await;
                None
            }
            Access::ReadOnly => {
                tx.commit().await.map_err(|e| classify(e, role))?;
                None
            }
            // A write is never cut short: the stream was drained, so the
            // statement completed, and it commits whether or not the
            // `RETURNING` rows were truncated. A failed commit is an error —
            // never success after a rollback.
            Access::ReadWrite => {
                tx.commit().await.map_err(|e| classify(e, role))?;
                Some(collected.rows_affected)
            }
        };
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
    result
}

/// Stream the statement, collecting rows until the budget runs out. A read
/// stops there (the caller cancels the rest); a write keeps draining so the
/// statement runs to completion and its `rows_affected` is exact.
async fn stream_rows(
    tx: &mut Transaction<'_, Postgres>,
    query: &ExecQuery<'_>,
    role: &str,
) -> Result<Collected, ExecError> {
    let mut budget = ResultBudget::new(query.row_limit);
    let mut collected = Collected {
        columns: Vec::new(),
        rows: Vec::new(),
        truncated: false,
        rows_affected: 0,
    };
    let mut decoders_for_rows = Vec::new();

    // Unnamed statement: ad-hoc SQL must not accumulate in the connection's
    // prepared-statement cache.
    let mut sqlx_query = sqlx::query(query.sql).persistent(false);
    for bind in query.binds {
        sqlx_query = sqlx_query.bind(*bind);
    }
    // `Executor::fetch_many` (not the deprecated `Query::fetch_many`) is the
    // one stream that yields the statement's completion — and with it
    // `rows_affected` — alongside its rows.
    let mut stream = (&mut **tx).fetch_many(sqlx_query);
    while let Some(item) = stream.next().await {
        let row = match item.map_err(|e| classify(e, role))? {
            Either::Left(done) => {
                collected.rows_affected += done.rows_affected();
                continue;
            }
            Either::Right(row) => row,
        };
        if collected.truncated {
            continue; // draining a write
        }
        if collected.columns.is_empty() {
            collected.columns = sqlx::Row::columns(&row)
                .iter()
                .map(|c| c.name().to_string())
                .collect();
            decoders_for_rows = decoders(&row);
        }
        // The row-cap check comes first so the row past the cap is never
        // decoded; the byte check needs the decoded row.
        let admitted = budget.has_row_left() && {
            let decoded = decode_row(&row, &decoders_for_rows);
            let fits = budget.admit(&decoded);
            if fits {
                collected.rows.push(decoded);
            }
            fits
        };
        if !admitted {
            collected.truncated = true;
            if query.access == Access::ReadOnly {
                break;
            }
        }
    }
    Ok(collected)
}

/// Column names for a zero-row result. Without them the caller cannot tell
/// "your filter matched nothing" from "that table has no such columns"
/// (#136). Parse/Describe only — the statement does not run again.
///
/// Best-effort on purpose: the query already succeeded, so a failure here
/// must not turn a good 0-row answer into an error.
async fn describe_columns(tx: &mut Transaction<'_, Postgres>, sql: &str) -> Vec<String> {
    match (&mut **tx).describe(sql).await {
        Ok(described) => described
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}
