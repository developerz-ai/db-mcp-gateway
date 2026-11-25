//! What happens to a connection between two callers: the session is wiped
//! before the pool hands it out again.

use futures::future::BoxFuture;
use sqlx::pool::PoolConnectionMetadata;
use sqlx::{Connection, Executor, PgConnection};

use super::error::{is_feature_not_supported, log_discarded};

/// Everything a caller can leave on a session that the transaction's end
/// does not undo. `RESET ALL` undoes session `SET`s / `set_config(…,
/// false)` but, by design, neither `role` nor `session_authorization`, so
/// both are reset by name. `DEALLOCATE ALL` drops whatever is still
/// prepared. `DISCARD SEQUENCES` forgets `lastval()` / `currval()`, which
/// would hand the next caller a key the previous one generated — at the
/// price of the values a `CACHE n` sequence preallocated for the session,
/// which live in the same state and go with it (spec 05);
/// `DISCARD TEMP` drops temporary tables and with them their rows. Not
/// `DISCARD ALL`, which does all of this: it refuses to run inside a batch.
/// The lexing pin goes last because `RESET ALL` would restore the server
/// default.
const RESET_SESSION: &str = "RESET ALL; RESET SESSION AUTHORIZATION; RESET ROLE; DEALLOCATE ALL; \
     DISCARD SEQUENCES; DISCARD TEMP; SET standard_conforming_strings = on";

/// The SQL guard reads `'\'` the way Postgres does only while backslashes in
/// plain literals are literal; a server configured otherwise would execute a
/// different statement from the one the guard admitted.
const PIN_LEXING: &str = "SET standard_conforming_strings = on";

/// `after_connect` hook: pin the lexing setting the guard relies on.
pub(super) fn pin_lexing(
    conn: &mut PgConnection,
    _meta: PoolConnectionMetadata,
) -> BoxFuture<'_, Result<(), sqlx::Error>> {
    Box::pin(async move { conn.execute(PIN_LEXING).await.map(|_| ()) })
}

/// Drops session advisory locks; appended to [`RESET_SESSION`].
const UNLOCK_ALL: &str = "SELECT pg_advisory_unlock_all()";

/// `after_release` hook: wipe session state before a connection serves the
/// next caller. A failed reset discards the connection.
///
/// The driver names no statement on these connections (see `config`), so it
/// has nothing of its own to close first. The read buffer is given back: one
/// huge row must not stay allocated on an idle connection.
///
/// A server without advisory locks (YugabyteDB with the preview flag off)
/// rejects the unlock as `feature_not_supported`; it can hold no advisory
/// lock, so the connection is kept. The rejected statement aborted the
/// implicit transaction the batch ran in, taking the resets with it, so
/// they are repeated alone.
pub(super) fn reset_on_release(
    conn: &mut PgConnection,
    _meta: PoolConnectionMetadata,
) -> BoxFuture<'_, Result<bool, sqlx::Error>> {
    Box::pin(async move {
        conn.shrink_buffers();
        let with_unlock = format!("{RESET_SESSION}; {UNLOCK_ALL}");
        let reset = match conn.execute(sqlx::AssertSqlSafe(with_unlock)).await {
            Err(err) if is_feature_not_supported(&err) => conn.execute(RESET_SESSION).await,
            other => other,
        };
        match reset {
            Ok(_) => Ok(true),
            Err(err) => {
                log_discarded(&err, None, "connection reset failed; discarding");
                Ok(false)
            }
        }
    })
}
