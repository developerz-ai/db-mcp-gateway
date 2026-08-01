//! Cancellation guard for the pg exec path — fires `pg_cancel_backend(pid)`
//! from a detached task if dropped while armed (CLAUDE.md
//! *§Cancellation safety*).
//!
//! Why this is necessary: when the agent disconnects, axum drops the handler
//! future and with it this query future, mid-`.await`. Dropping a sqlx
//! `Transaction` does NOT stop the query already running on the Postgres
//! backend — it only closes the client socket. The backend keeps executing
//! until it finishes or hits `statement_timeout`, pinning a pool connection
//! for up to the full timeout after the client is gone. So we capture the
//! backend PID up front and, on drop, cancel it over the **cancel pool** —
//! a pool that is deliberately separate from the query pool. Using the
//! query pool would have `execute` queue on `acquire()` behind the very
//! connections the cancels are trying to free (see
//! [`super::CANCEL_POOL_MAX_CONNECTIONS`]).
//!
//! Disarmed on the normal path once the query has run to completion, so a
//! cleanly-returned connection is never targeted — otherwise a late cancel
//! could hit an unrelated query that reused the same backend PID.

use sqlx::PgPool;

pub(super) struct CancelOnDrop {
    /// `Some` while armed: the cancel pool (never the main query pool) and
    /// the backend PID to cancel.
    armed: Option<(PgPool, i32)>,
}

impl CancelOnDrop {
    pub(super) fn armed(cancel_pool: PgPool, pid: i32) -> Self {
        Self {
            armed: Some((cancel_pool, pid)),
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some((pool, pid)) = self.armed.take() else {
            return;
        };
        // Detached: the parent future is being dropped, so we can't await the
        // cancel inline. The spawn outlives this Drop and runs on a fresh
        // connection. No error Display in the log — this is the request path,
        // and `pid` alone tells the operator which backend failed to cancel.
        tokio::spawn(async move {
            if sqlx::query("SELECT pg_cancel_backend($1)")
                .bind(pid)
                .execute(&pool)
                .await
                .is_err()
            {
                tracing::warn!(pid, "pg_cancel_backend on drop failed");
            }
        });
    }
}
