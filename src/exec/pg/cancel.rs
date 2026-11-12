//! Cancellation for the pg exec path: an identity-checked
//! `pg_cancel_backend`, and the drop guard that fires it if the query future
//! is dropped while armed (CLAUDE.md *§Cancellation safety*).
//!
//! Why the guard is necessary: when the agent disconnects, axum drops the
//! handler future and with it this query future, mid-`.await`. Dropping a
//! sqlx `Transaction` does NOT stop the query already running on the
//! Postgres backend — it only closes the client socket. The backend keeps
//! executing until it finishes or hits `statement_timeout`, pinning a pool
//! connection for up to the full timeout after the client is gone. So we
//! capture the backend up front and, on drop, cancel it over the **cancel
//! pool** — a pool that is deliberately separate from the query pool. Using
//! the query pool would have `execute` queue on `acquire()` behind the very
//! connections the cancels are trying to free (see
//! [`super::CANCEL_POOL_MAX_CONNECTIONS`]).
//!
//! Why the identity check: a PID alone is not an identity. A cancel that
//! lands late — the detached drop task, or a truncation cancel racing a
//! fast commit — could hit the *next* query that pooled backend runs. Each
//! transaction therefore sets `application_name` to a fresh [`BackendTag`]
//! (`SET LOCAL`, so it reverts at commit), and the cancel only fires while
//! that backend still carries the tag.

use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::drain::DetachedTasks;

/// The cancel statement. `pg_stat_activity` shows the caller's own backends
/// in full, and the cancel pool connects as the same role.
const CANCEL_SQL: &str = "SELECT pg_cancel_backend(pid) FROM pg_stat_activity \
                          WHERE pid = $1 AND application_name = $2";

/// Per-transaction `application_name`. Built only from a UUID, so it is safe
/// to interpolate into `SET LOCAL` (no quote can appear in it) and fits in
/// Postgres' 63-byte `application_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTag(String);

impl BackendTag {
    pub(super) fn new() -> Self {
        Self(format!("dbmcp-{}", Uuid::new_v4().simple()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// One running query's backend: its PID and the tag its transaction set.
#[derive(Debug, Clone)]
pub(super) struct Backend {
    pub(super) pid: i32,
    pub(super) tag: BackendTag,
}

/// Cancel `backend` if it is still running the tagged transaction. Not
/// matching (the backend moved on, or is gone) is success: there is nothing
/// left to cancel. Errors are the caller's to log — never with `Display`.
pub(super) async fn cancel_backend(
    cancel_pool: &PgPool,
    backend: &Backend,
) -> Result<(), sqlx::Error> {
    sqlx::query(CANCEL_SQL)
        .bind(backend.pid)
        .bind(backend.tag.as_str())
        .execute(cancel_pool)
        .await
        .map(|_| ())
}

pub(super) struct CancelOnDrop {
    /// `Some` while armed: the cancel pool (never the main query pool) and
    /// the backend to cancel.
    armed: Option<(PgPool, Backend)>,
    /// Where the detached cancel runs, so shutdown waits for it.
    detached: DetachedTasks,
}

impl CancelOnDrop {
    pub(super) fn armed(cancel_pool: PgPool, backend: Backend, detached: DetachedTasks) -> Self {
        Self {
            armed: Some((cancel_pool, backend)),
            detached,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let Some((pool, backend)) = self.armed.take() else {
            return;
        };
        // Detached: the parent future is being dropped, so we can't await the
        // cancel inline. The task outlives this Drop, runs on a fresh
        // connection, and is tracked so a shutdown drain waits for it. No
        // error Display in the log — this is the request path, and `pid`
        // alone tells the operator which backend failed to cancel.
        self.detached.spawn(async move {
            if cancel_backend(&pool, &backend).await.is_err() {
                tracing::warn!(pid = backend.pid, "pg_cancel_backend on drop failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_unique_quote_free_and_fits_application_name() {
        let (a, b) = (BackendTag::new(), BackendTag::new());
        assert_ne!(a, b);
        assert!(a.as_str().len() <= 63, "{}", a.as_str());
        assert!(
            a.as_str()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "{}",
            a.as_str()
        );
    }
}
