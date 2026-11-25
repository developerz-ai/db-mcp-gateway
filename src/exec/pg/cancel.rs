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
//! [`super::cancel_pool`]).
//!
//! Why the identity check: a PID alone is not an identity. A cancel that
//! lands late — the detached drop task, or a truncation cancel racing a
//! fast commit — could hit the *next* query that pooled backend runs. Each
//! transaction therefore sets `application_name` to a fresh [`BackendTag`]
//! (`SET LOCAL`, so it reverts at commit), and the cancel only fires while
//! that backend still carries the tag. The tag also names the gateway
//! request the transaction runs for, which is what `db_activity` reports and
//! `cancel_request` matches on.

use std::fmt;

use sqlx::{Executor, PgPool};
use uuid::Uuid;

use crate::audit::drain::DetachedTasks;

/// Every tag of one request starts with this. It is a UUID, so it renders as
/// `dbmcp-<32 lowercase hex digits>-` and nothing else: no quote, no `LIKE`
/// wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RequestPrefix(Uuid);

impl RequestPrefix {
    pub(super) fn of(request_id: Uuid) -> Self {
        Self(request_id)
    }
}

impl fmt::Display for RequestPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dbmcp-{}-", self.0.simple())
    }
}

/// Per-transaction `application_name`: `dbmcp-<request id>-<nonce>`, both in
/// lowercase hex. It holds numbers, never text, so it is safe to interpolate
/// between quotes — there is no tag whose rendering contains one — and fits
/// in Postgres' 63-byte `application_name` (47 bytes). The nonce keeps two
/// transactions of one request apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BackendTag {
    request: RequestPrefix,
    nonce: u32,
}

impl BackendTag {
    /// Captures the request id of a tag in `pg_stat_activity` (a POSIX regex,
    /// no quote in it).
    pub(super) const REQUEST_ID_PATTERN: &'static str = "^dbmcp-([0-9a-f]{32})-[0-9a-f]{8}$";

    pub(super) fn for_request(request_id: Uuid) -> Self {
        Self {
            request: RequestPrefix::of(request_id),
            nonce: Uuid::new_v4().as_fields().0,
        }
    }
}

impl fmt::Display for BackendTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:08x}", self.request, self.nonce)
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
///
/// A simple query, because it runs outside a transaction: a transaction-mode
/// pooler may send a `Parse` and the `Bind` after it to two backends, and
/// the `Bind` would then run whatever another caller last parsed there.
/// `pg_stat_activity` shows the caller's own backends in full, and the
/// cancel pool connects as the same role.
pub(super) async fn cancel_backend(
    cancel_pool: &PgPool,
    backend: &Backend,
) -> Result<(), sqlx::Error> {
    let sql = format!(
        "SELECT pg_cancel_backend(pid) FROM pg_stat_activity \
         WHERE pid = {} AND application_name = '{}'",
        backend.pid, backend.tag
    );
    cancel_pool
        .execute(sqlx::AssertSqlSafe(sql))
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
    fn two_transactions_of_one_request_have_different_tags() {
        let request = Uuid::new_v4();
        let (a, b) = (
            BackendTag::for_request(request),
            BackendTag::for_request(request),
        );
        assert_ne!(a, b);
        let prefix = RequestPrefix::of(request).to_string();
        assert!(a.to_string().starts_with(&prefix) && b.to_string().starts_with(&prefix));
    }

    #[test]
    fn request_id_pattern_matches_the_tag_shape() {
        let request = Uuid::new_v4();
        let tag = BackendTag::for_request(request).to_string();
        let hex = request.simple().to_string();
        assert_eq!(&tag["dbmcp-".len().."dbmcp-".len() + 32], hex);
        assert!(!BackendTag::REQUEST_ID_PATTERN.contains('\''));
    }

    proptest::proptest! {
        /// Whatever it holds, a tag renders as one plain word that fits in
        /// `application_name`, and its prefix as one `LIKE` cannot expand.
        #[test]
        fn no_tag_renders_anything_but_hex_and_hyphens(id: u128, nonce: u32) {
            let request = RequestPrefix::of(Uuid::from_u128(id));
            let tag = BackendTag { request, nonce }.to_string();
            proptest::prop_assert_eq!(tag.len(), "dbmcp-".len() + 32 + 1 + 8);
            let words: Vec<&str> = tag.split('-').collect();
            proptest::prop_assert!(words.len() == 3 && words[0] == "dbmcp", "{}", tag);
            let hex = |word: &str| word.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            proptest::prop_assert!(hex(words[1]) && hex(words[2]), "{}", tag);
            proptest::prop_assert_eq!(request.to_string(), format!("dbmcp-{}-", words[1]));
        }
    }
}
