//! Read truncation cleanup — cancel the backend generating rows nobody asked
//! for, then roll back the aborted transaction.
//!
//! Why this exists: sqlx always issues the extended-protocol portal `Execute`
//! with `limit: 0` (no server-side row cap — deliberate, to avoid
//! parallel-worker pessimization), so breaking out of the Rust-side read
//! loop at N does NOT stop Postgres from generating and queueing the rest
//! of the result set. The pooled connection cannot accept the next command
//! — `COMMIT` included — until that queued traffic is fully read:
//! `wait_until_ready` drains it silently on the next `.await` on this
//! connection. That defeats the row cap on exactly the queries where it
//! matters: a query big enough to need truncating is a query where draining
//! "the rest" is the expensive part.
//!
//! Cancel the backend instead — the same mechanism [`super::cancel::CancelOnDrop`]
//! uses for a client disconnect, just invoked inline. Postgres checks for a
//! pending cancel between row-generation steps, so the backend aborts
//! server-side in short order rather than continuing to produce rows nobody
//! asked for.
//!
//! Reads only. A truncated *write* is drained and committed instead (see
//! `run`): rolling it back would report rows as written that were not.

use sqlx::{PgPool, Postgres, Transaction};

use super::cancel::{Backend, cancel_backend};

/// Cancel the backend then roll back the (aborted) read transaction. Cleanup
/// outcome is deliberately NOT propagated to the caller: the truncated rows
/// already collected are the result, and a valid truncated read must not be
/// turned into a client-visible failure by cleanup noise.
///
/// A cancel that matches no backend is accepted without a warning —
/// equivalent to success. Cancellation execution errors and `rollback`
/// errors are logged at `warn` for operator observability but never surfaced
/// to the client. Contract documented in
/// `website/docs/initial-idea/05-credentials.md`.
pub(super) async fn cancel_and_rollback(
    tx: Transaction<'_, Postgres>,
    cancel_pool: &PgPool,
    backend: &Backend,
) {
    // Same log shape as `CancelOnDrop::drop` — pid is enough for the operator
    // to find the backend; sqlx error text is not included because its
    // Display can quote the DSN on some variants (Configuration), and the
    // request path never leaks credentials.
    if cancel_backend(cancel_pool, backend).await.is_err() {
        tracing::warn!(pid = backend.pid, "pg_cancel_backend on truncation failed");
    }
    // The backend is now in an aborted-transaction state — only ROLLBACK is
    // valid on it, and this is a read-only transaction with nothing to lose.
    if tx.rollback().await.is_err() {
        tracing::warn!(pid = backend.pid, "rollback after truncation failed");
    }
}
