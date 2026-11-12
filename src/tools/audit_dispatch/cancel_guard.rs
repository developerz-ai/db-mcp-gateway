//! Drop-fired fallback audit write: the reason no dispatch — cancelled
//! mid-work or failed mid-audit — ends without an attempted audit row.

use metrics::counter;
use sqlx::PgPool;

use crate::audit::{self, AuditRow};
use crate::config::StreamSinkConfig;

use super::{Outcome, OutcomeCode, metric_names::TOOL_CALLS};

/// Drop-fired guard that writes a `"cancelled"` audit row if the dispatch
/// future is dropped before `disarm()` is called. The detached
/// `tokio::spawn` lets the audit write outlive the cancellation.
///
/// Why this shape: when an agent disconnects, axum drops the handler
/// future, which drops the in-flight `audit_dispatch` future mid-`.await`.
/// Without a guard, the audit row is never written. We can't use async
/// `Drop` (doesn't exist in Rust today), so we spawn the write on the
/// runtime instead — the spawned task runs to completion independently
/// of the parent future's lifecycle.
///
/// Server-side query cancellation is handled separately, in the exec layer:
/// `PgAdapter` captures the backend PID and fires `pg_cancel_backend` from a
/// detached task on drop, because dropping a `sqlx::Transaction` only closes
/// the socket — it does NOT stop the query already running on the backend.
/// (Mongo relies on `maxTimeMS` plus cursor-drop.) This guard's only job is
/// the audit row.
pub(super) struct CancelledAuditGuard {
    /// The row the fallback writes. `outcome` stays empty until
    /// `record_outcome`.
    pub(super) row: AuditRow,
    /// `Some` while armed; `disarm()` clears it and `Drop` then writes
    /// nothing. Cloned pool handle — needed inside the spawned task.
    /// `PgPool` is `Arc`-internally so cloning is cheap.
    pub(super) state_db: Option<PgPool>,
    /// Tool name kept separately for the metric counter emitted from the
    /// drop path (audit row's `tool` field is moved into the spawn).
    pub(super) tool: &'static str,
    /// Owned copy — the spawned task outlives the borrow `audit_dispatch`
    /// holds. Cheap: at most a handful of enum variants.
    pub(super) stream_sinks: Vec<StreamSinkConfig>,
}

impl CancelledAuditGuard {
    pub(super) fn disarm(mut self) {
        self.state_db = None;
    }

    /// Record the tool's actual outcome on the pre-built row and return the
    /// row the primary write persists. Called after `work.await` completes
    /// so the guard's fallback write — fired if the dispatch future is
    /// dropped or the primary `audit::log` fails — carries the real outcome
    /// rather than the placeholder `"cancelled"` that `finalize_dropped_row`
    /// falls back to when the outcome was never set.
    pub(super) fn record_outcome(&mut self, outcome: &Outcome) -> AuditRow {
        let row = &mut self.row;
        row.outcome = outcome.code.as_str().to_string();
        row.elapsed_ms = outcome.elapsed_ms;
        row.row_count = outcome.row_count;
        row.truncated = outcome.truncated;
        row.error_message = outcome.error_message.clone();
        // The guard keeps its copy for the fallback; the caller's copy is
        // the primary write.
        row.clone()
    }
}

/// If the tool never got to set an outcome, the drop is firing mid-work —
/// the true outcome is unknown, so tag it `"cancelled"` and stamp the
/// error_message so operators can distinguish it from a forbidden row at a
/// glance. If the outcome IS set, the drop is firing AFTER work completed
/// (the primary `audit::log` failed, timed out, or the future was dropped
/// mid-audit) and the real outcome must be preserved for the retry.
fn finalize_dropped_row(row: &mut AuditRow) {
    if row.outcome.is_empty() {
        row.outcome = OutcomeCode::Cancelled.as_str().to_string();
        row.error_message = Some("client disconnected before completion".to_string());
    }
}

impl Drop for CancelledAuditGuard {
    fn drop(&mut self) {
        let Some(pool) = self.state_db.take() else {
            return;
        };
        // Owned copy for the spawned task, which outlives `self`.
        let mut row = self.row.clone();
        // If the outcome was already recorded, `audit_dispatch` already
        // emitted the primary TOOL_CALLS increment. Emitting it again here
        // would double-count every audit-failure path. Only count in Drop
        // for the mid-work cancellation branch where `finalize_dropped_row`
        // promotes the empty outcome to `"cancelled"` and no primary
        // increment ever ran.
        let outcome_was_recorded = !row.outcome.is_empty();
        finalize_dropped_row(&mut row);
        if !outcome_was_recorded {
            counter!(
                TOOL_CALLS,
                "tool" => self.tool,
                "outcome" => OutcomeCode::Cancelled.as_str(),
            )
            .increment(1);
        }
        // Detached spawn. We can't await it; if it fails, there's no
        // surface to report the failure to — the agent already disconnected
        // (or the primary write already returned an error the caller saw).
        // `audit::log` has its own timeout so a wedged state DB does not
        // stall the detached task forever. The row shares `id` with any
        // prior primary write, so `ON CONFLICT (id) DO NOTHING` makes this
        // second attempt idempotent.
        let stream_sinks = std::mem::take(&mut self.stream_sinks);
        tokio::spawn(async move {
            match audit::log(&pool, &row).await {
                Ok(()) => audit::stream::send(&stream_sinks, &row),
                Err(err) => tracing::error!(%err, "fallback audit row write failed"),
            }
        });
    }
}

#[cfg(test)]
#[path = "cancel_guard_tests.rs"]
mod tests;
