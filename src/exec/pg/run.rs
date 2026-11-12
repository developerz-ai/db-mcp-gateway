//! Per-query transaction orchestration: pin a backend, arm the cancel
//! guard, apply the DB-side `statement_timeout`, stream rows up to the cap.

use std::time::Instant;

use futures::StreamExt;
use serde_json::Value;
use sqlx::{Column, Executor, PgPool, Row};

use super::super::adapter::{ExecError, ExecQuery, ExecResult, effective_timeout_ms};
use super::cancel::CancelOnDrop;
use super::decode::{classify, decode_row};
use super::truncate::cancel_and_rollback;

pub(super) async fn run_query_inner(
    pool: &PgPool,
    cancel_pool: &PgPool,
    query: &ExecQuery<'_>,
) -> Result<ExecResult, ExecError> {
    let started = Instant::now();
    let mut tx = pool.begin().await.map_err(|_| ExecError::Unavailable)?;

    // Capture this connection's backend PID so a drop (agent disconnect) can
    // cancel the exact backend running our query — dropping `tx` alone won't
    // stop it. Armed now and disarmed only after a clean commit below. The
    // guard holds the *cancel* pool so `pg_cancel_backend` can always
    // acquire, even when every connection in the query pool is pinned by
    // stuck backends.
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .map_err(classify)?;
    let mut cancel = CancelOnDrop::armed(cancel_pool.clone(), pid);

    // Run the statement under the guard. By the time this block resolves — Ok
    // OR Err — the backend has stopped executing our query, so we disarm
    // before returning. The guard stays armed ONLY if this future is dropped
    // while awaiting (agent disconnect / outer `tokio::time::timeout`): the
    // one case where the backend is still running and must be cancelled.
    // Disarming on every normal return prevents a stray `pg_cancel_backend(pid)`
    // from cancelling an unrelated statement that later reuses this pooled
    // backend (same PID) — a flake where a timeout's detached cancel landed
    // mid-next-query and turned a healthy result into a spurious error.
    let result: Result<ExecResult, ExecError> = async {
        // Always set a DB-side cap — the grant value clamped to the gateway
        // ceiling, never `None` (see S4). `ms` is u32, so the SQL fragment is
        // purely a number — no injection risk from interpolation.
        let ms = effective_timeout_ms(query.statement_timeout_ms);
        let stmt = format!("SET LOCAL statement_timeout = {ms}");
        tx.execute(stmt.as_str()).await.map_err(classify)?;

        let limit = query.row_limit as usize;
        let mut columns: Vec<String> = Vec::new();
        let mut rows: Vec<Vec<Value>> = Vec::new();
        let mut truncated = false;

        {
            let mut sqlx_query = sqlx::query(query.sql);
            for bind in query.binds {
                sqlx_query = sqlx_query.bind(*bind);
            }
            let mut stream = sqlx_query.fetch(&mut *tx);
            while let Some(row_result) = stream.next().await {
                let row = row_result.map_err(classify)?;
                if columns.is_empty() {
                    columns = row.columns().iter().map(|c| c.name().to_string()).collect();
                }
                if rows.len() >= limit {
                    truncated = true;
                    break;
                }
                rows.push(decode_row(&row));
            }
            // Stream is dropped here so the borrow on `tx` ends.
        }

        // A zero-row result never enters the loop above, so `columns` would
        // stay empty and the caller could not tell "your filter matched
        // nothing" from "that table has no such columns" (#136). Ask the
        // server to describe the statement — Parse/Describe only, the query
        // does not run a second time.
        //
        // Best-effort on purpose: the query already succeeded, so a failure
        // here must not turn a good 0-row answer into an error. Worst case we
        // fall back to the previous (empty) behaviour.
        if columns.is_empty()
            && let Ok(described) = tx.describe(query.sql).await
        {
            columns = described
                .columns()
                .iter()
                .map(|c| c.name().to_string())
                .collect();
        }

        if truncated {
            // Truncation cleanup: cancel the backend so it stops generating
            // rows nobody asked for, then rollback the (now-aborted) tx.
            // Cleanup failures are logged at `warn` but do NOT fail the
            // request — see [`truncate::cancel_and_rollback`] and
            // `website/docs/initial-idea/05-credentials.md` for the contract.
            cancel_and_rollback(tx, cancel_pool, pid).await;
        } else {
            tx.commit().await.map_err(classify)?;
        }

        Ok(ExecResult {
            columns,
            rows,
            truncated,
            elapsed_ms: started.elapsed().as_millis() as u64,
        })
    }
    .await;
    // Statement finished (success or error) — no orphaned backend to cancel.
    cancel.disarm();
    result
}
