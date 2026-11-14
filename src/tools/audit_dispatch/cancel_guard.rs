//! Drop-fired fallback audit write: the reason no dispatch — cancelled
//! mid-work or failed mid-audit — ends without an attempted audit row.

use metrics::counter;
use sqlx::PgPool;

use crate::audit::drain::DetachedTasks;
use crate::audit::intent::WRITE_MAY_HAVE_COMMITTED;
use crate::audit::stream::StreamSinks;
use crate::audit::{self, AuditRow, OutcomeCode};
use crate::exec::Access;

use super::Outcome;
use super::metric_names::{ACCESS_UNKNOWN, AUDIT_FALLBACK_FAILURES, TOOL_CALLS};

const DISCONNECTED: &str = "client disconnected before completion";

/// Drop-fired guard that writes the dispatch's audit row if the dispatch
/// future is dropped before `disarm()` is called.
///
/// Why this shape: when an agent disconnects, axum drops the handler
/// future, which drops the in-flight `audit_dispatch` future mid-`.await`.
/// Without a guard, the audit row is never written. There is no async
/// `Drop`, so the write runs on [`DetachedTasks`]: it outlives the
/// cancelled request, and `main` drains it at shutdown instead of dropping
/// it with the runtime.
///
/// Server-side query cancellation is handled separately, in the exec layer:
/// `PgAdapter` captures the backend PID and fires `pg_cancel_backend` from a
/// detached task on drop, because dropping a `sqlx::Transaction` only closes
/// the socket — it does NOT stop the query already running on the backend.
/// (Mongo relies on `maxTimeMS` plus cursor-drop.) This guard's only job is
/// the audit row.
pub(super) struct CancelledAuditGuard {
    /// The row the fallback writes. Starts as the `cancelled` row; the
    /// recorders overwrite it as the dispatch progresses.
    pub(super) row: AuditRow,
    /// `false` while the work is still running — the only state in which
    /// the drop path, not the dispatch, counts the call.
    pub(super) completed: bool,
    /// `Some` while armed; `disarm()` clears it and `Drop` then writes
    /// nothing. `PgPool` is `Arc`-internally so cloning is cheap.
    pub(super) state_db: Option<PgPool>,
    /// The metric label; `row.tool` is an owned copy for the write.
    pub(super) tool: &'static str,
    pub(super) sinks: StreamSinks,
    pub(super) tasks: DetachedTasks,
}

impl CancelledAuditGuard {
    /// Arm the guard on `row`, stamped `cancelled` until an outcome is
    /// recorded.
    pub(super) fn arm(
        mut row: AuditRow,
        tool: &'static str,
        state_db: PgPool,
        sinks: StreamSinks,
        tasks: DetachedTasks,
    ) -> Self {
        row.outcome = OutcomeCode::Cancelled;
        row.error_message = Some(DISCONNECTED.to_string());
        Self {
            tool,
            row,
            completed: false,
            state_db: Some(state_db),
            sinks,
            tasks,
        }
    }

    pub(super) fn disarm(mut self) {
        self.state_db = None;
    }

    /// Record the tool's actual outcome and return the row the primary write
    /// persists. The guard keeps an identical copy (same `id`), so a fallback
    /// fired by a drop during the primary write is idempotent with it.
    pub(super) fn record_outcome(&mut self, outcome: &Outcome) -> AuditRow {
        let row = &mut self.row;
        row.outcome = outcome.code;
        row.elapsed_ms = outcome.elapsed_ms;
        row.row_count = outcome.row_count;
        row.truncated = outcome.truncated;
        row.error_message = outcome.error_message.clone();
        row.rows_affected = outcome.write.and_then(|w| w.rows_affected);
        self.completed = true;
        row.clone()
    }

    /// The primary write failed, so the client is told `audit_unavailable`.
    /// The fallback row records that — the code the client saw — and keeps
    /// the tool's own outcome in `error_message`.
    pub(super) fn record_audit_failure(&mut self) {
        let row = &mut self.row;
        let tool_outcome = match row.error_message.take() {
            Some(message) => format!("tool outcome {}: {message}", row.outcome),
            None => format!("tool outcome {}", row.outcome),
        };
        row.outcome = OutcomeCode::AuditUnavailable;
        row.error_message = Some(tool_outcome);
    }
}

impl Drop for CancelledAuditGuard {
    fn drop(&mut self) {
        let Some(pool) = self.state_db.take() else {
            return;
        };
        if !self.completed {
            // Mid-work drop: the dispatch never reached its own count.
            counter!(
                TOOL_CALLS,
                "tool" => self.tool,
                "outcome" => OutcomeCode::Cancelled.as_str(),
                // The access is decided inside the dropped work.
                "access" => ACCESS_UNKNOWN,
            )
            .increment(1);
        }
        let mut row = self.row.clone();
        let sinks = self.sinks.clone();
        let tasks = self.tasks.clone();
        let dropped_mid_work = !self.completed;
        // `audit::log` and the intent lookup have their own deadlines, so
        // this cannot run unbounded. Nobody awaits it — the client is gone
        // or already got its error — so a failure is surfaced by log line
        // and counter only.
        self.tasks.spawn(async move {
            if dropped_mid_work {
                note_write_access(&pool, &mut row).await;
            }
            match audit::log(&pool, &row).await {
                Ok(()) => sinks.send(&row, &tasks),
                Err(err) => {
                    counter!(AUDIT_FALLBACK_FAILURES).increment(1);
                    tracing::error!(
                        %err,
                        class = %err.class(),
                        request_id = %row.request_id,
                        outcome = %row.outcome,
                        "fallback audit row write failed"
                    );
                }
            }
        });
    }
}

/// A dispatch dropped mid-work may have been dropped mid-commit. The work
/// that knew its access is gone, so ask the intent it committed: a write is
/// flagged as possibly committed. A failed lookup still writes the row.
async fn note_write_access(pool: &PgPool, row: &mut AuditRow) {
    match audit::intent::access_of(pool, &row.request_id).await {
        Ok(Some(Access::ReadWrite)) => {
            let message = row.error_message.as_deref().unwrap_or(DISCONNECTED);
            row.error_message = Some(format!("{message} ({WRITE_MAY_HAVE_COMMITTED})"));
        }
        Ok(Some(Access::ReadOnly) | None) => {}
        Err(err) => tracing::warn!(
            %err,
            class = %err.class(),
            request_id = %row.request_id,
            "intent access lookup failed; cancelled row carries no access"
        ),
    }
}

#[cfg(test)]
#[path = "cancel_guard_tests.rs"]
mod tests;
