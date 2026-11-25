//! `sqlx::Error` → [`ExecError`], and the one log line per discarded error.
//!
//! Nothing here renders an error with `Display`: connect-phase sqlx errors
//! can quote the DSN (`Configuration`) or name the role and host, and the
//! request path never leaks credentials. Logs carry the variant name, the
//! SQLSTATE and the [`Origin`] only; the agent gets the SQLSTATE and the gateway's wording for
//! a statement-level error (see [`super::redact`]) and an opaque code for
//! everything else.

use sqlx::error::DatabaseError;
use sqlx::postgres::{PgDatabaseError, PgErrorPosition, PgSeverity};
use uuid::Uuid;

use super::super::adapter::ExecError;
use super::super::rejection::DbRejection;
use super::super::sql_guard::Access;
use super::redact::{rejection_message, safe_hint};

/// Where a target error came from. The names go on its log line as event
/// fields — the operator's log shows no span, so a line without them cannot
/// be tied to a request or a database. `role` is never logged: it is what
/// gets redacted from a server message.
#[derive(Debug, Clone, Copy)]
pub(super) struct Origin<'a> {
    pub(super) server: &'a str,
    pub(super) database: &'a str,
    pub(super) role: &'a str,
    /// `None` for work no request asked for (a pool opening).
    pub(super) request_id: Option<Uuid>,
}

/// Classify an error raised while `sql` ran — the caller's statement, or
/// `""` for one of the gateway's own.
pub(super) fn classify(err: sqlx::Error, origin: &Origin<'_>, sql: &str) -> ExecError {
    log_discarded(&err, Some(origin), "target statement failed");
    if is_stale_plan(&err) {
        return ExecError::Unavailable;
    }
    if let sqlx::Error::Database(db) = &err
        && let Some(code) = db.code()
    {
        return match code.as_ref() {
            // `statement_timeout` raises `57014` (`query_canceled`).
            QUERY_CANCELED => ExecError::Timeout,
            // Connection exception, operator intervention (backend
            // terminated, server shutting down), insufficient resources:
            // the target, not the statement, is the problem. `08P01` is the
            // code a placeholder without a param is refused with, too.
            c if c.starts_with("57P") || c.starts_with("53") => ExecError::Unavailable,
            c if c.starts_with("08") && !(c == "08P01" && judges_a_statement(db.as_ref())) => {
                ExecError::Unavailable
            }
            // The statement was sound and the target could not finish it
            // this time; nothing in the SQL is there to fix.
            c if rolled_back_by_the_target(c) => ExecError::Unavailable,
            // Invalid authorization: a login refusal, whose text names the
            // role and can name the client address. Never passed on, however
            // it got here.
            c if c.starts_with("28") => ExecError::Connection,
            c if not_the_statements(c, db.as_ref()) => ExecError::Unavailable,
            c => ExecError::Rejected(rejection(c, db.as_ref(), origin.role, sql)),
        };
    }
    if matches!(err, sqlx::Error::PoolTimedOut | sqlx::Error::Io(_)) {
        return ExecError::Unavailable;
    }
    ExecError::Sql
}

/// A statement-level refusal: the gateway's wording, the error position, and
/// the server's hint when [`safe_hint`] admits it. `DETAIL` is never read.
fn rejection(sqlstate: &str, db: &dyn DatabaseError, role: &str, sql: &str) -> DbRejection {
    let position = error_position(db);
    let hint = db
        .try_downcast_ref::<PgDatabaseError>()
        .and_then(PgDatabaseError::hint);
    let message = rejection_message(sqlstate, position, sql);
    DbRejection::new(sqlstate, &message, role)
        .with_position(position)
        .with_hint(safe_hint(sqlstate, position, sql, hint), role)
}

/// Whether an error the SQLSTATE alone would blame on the statement is a
/// pooler's, or the end of the session: any `FATAL` (pgcat's answer for every
/// failure of its own is a `FATAL` `58000`; PgBouncer passes on the server's
/// refusal of *its* login as one), and class `58`, system error, unless the
/// server raised it for the statement.
fn not_the_statements(sqlstate: &str, db: &dyn DatabaseError) -> bool {
    is_fatal(db) || (sqlstate.starts_with("58") && !judges_a_statement(db))
}

/// Whether the server raised this error for a statement and the session goes
/// on.
fn judges_a_statement(db: &dyn DatabaseError) -> bool {
    !is_fatal(db) && has_source_location(db)
}

/// Postgres names the source location in every error; a pooler answering for
/// a server it cannot reach has none.
fn has_source_location(db: &dyn DatabaseError) -> bool {
    db.try_downcast_ref::<PgDatabaseError>()
        .is_some_and(|db| db.file().is_some() || db.routine().is_some())
}

/// `FATAL` and `PANIC` end the session. No statement's own error does.
fn is_fatal(db: &dyn DatabaseError) -> bool {
    db.try_downcast_ref::<PgDatabaseError>()
        .is_some_and(|db| matches!(db.severity(), PgSeverity::Fatal | PgSeverity::Panic))
}

/// SQLSTATEs with which the target itself rolled the transaction back, for
/// a reason a retry can clear: `40001` (serialization failure — routine on
/// YugabyteDB, reads included), `40P01` (deadlock victim), and the session
/// ended for sitting in a transaction (`25P03`) or running one too long
/// (`25P04`).
fn rolled_back_by_the_target(sqlstate: &str) -> bool {
    matches!(sqlstate, "40001" | "40P01" | "25P03" | "25P04")
}

/// Where in the submitted statement the server located the error: a 1-based
/// character offset. An offset into a query the server generated itself
/// (inside a function body) is not one.
fn error_position(db: &dyn DatabaseError) -> Option<usize> {
    match db.try_downcast_ref::<PgDatabaseError>()?.position()? {
        PgErrorPosition::Original(at) => Some(at),
        PgErrorPosition::Internal { .. } => None,
    }
}

/// Classify a failed `COMMIT`. A server refusal (deferred constraint,
/// serialization failure) means the transaction rolled back, so it keeps its
/// statement-level classification. Anything else on a write — the link
/// dropped, the reply was unreadable, a pooler answered (a refused login
/// included: it is the pooler's, on its way back to the server) — leaves the
/// commit's fate unknown, which the caller must not report as "nothing
/// happened". A cancel or timeout is unknown to every caller as it is.
pub(super) fn classify_commit(
    err: sqlx::Error,
    access: Access,
    origin: &Origin<'_>,
    sql: &str,
) -> ExecError {
    let db = err.as_database_error();
    let refused = db.is_some_and(judges_a_statement);
    let rolled_back = db.is_some_and(|db| {
        (!is_fatal(db) || has_source_location(db))
            && db.code().is_some_and(|c| rolled_back_by_the_target(&c))
    });
    match classify(err, origin, sql) {
        ExecError::Unavailable | ExecError::Sql if access == Access::ReadWrite && !rolled_back => {
            ExecError::CommitIndeterminate
        }
        ExecError::Connection if access == Access::ReadWrite && !refused => {
            ExecError::CommitIndeterminate
        }
        other => other,
    }
}

/// "cached plan must not change result type" of the statement itself: a
/// definition changed between its `Parse` and its `Bind`. Revalidation comes
/// before execution, so nothing ran and the same call, planned afresh, may
/// succeed. Told from any other `0A000` by the raising C function: the
/// message is localised, the function name is not.
///
/// Raised by a plan the statement's own functions keep, it has a context: by
/// then the statement was running, its side effects outside the transaction
/// (a session lock, a sequence) stand, and the function may fail the same
/// way every time. That one is the statement's error, not a retry.
fn is_stale_plan(err: &sqlx::Error) -> bool {
    is_feature_not_supported(err)
        && err
            .as_database_error()
            .and_then(|db| db.try_downcast_ref::<PgDatabaseError>())
            .is_some_and(|db| {
                db.routine() == Some("RevalidateCachedQuery") && db.r#where().is_none()
            })
}

/// SQLSTATE `57014`: a cancel, or `statement_timeout`.
const QUERY_CANCELED: &str = "57014";

pub(super) fn is_query_canceled(err: &sqlx::Error) -> bool {
    sqlstate(err).as_deref() == Some(QUERY_CANCELED)
}

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    match err {
        sqlx::Error::Database(db) => db.code().map(|code| code.into_owned()),
        _ => None,
    }
}

/// Why acquiring a connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AcquireFailure {
    /// The target refused the credentials (SQLSTATE class `28`): the
    /// password may have rotated, so the adapter must be replaced.
    Auth,
    /// Anything else: the target is down, saturated, or misconfigured.
    Other,
}

impl AcquireFailure {
    pub(super) fn of(err: &sqlx::Error, origin: &Origin<'_>) -> Self {
        log_discarded(err, Some(origin), "target connection failed");
        match err {
            sqlx::Error::Database(db) if db.code().is_some_and(|c| c.starts_with("28")) => {
                Self::Auth
            }
            _ => Self::Other,
        }
    }
}

/// SQLSTATE `0A000`: the server lacks the feature the statement needs.
const FEATURE_NOT_SUPPORTED: &str = "0A000";

pub(super) fn is_feature_not_supported(err: &sqlx::Error) -> bool {
    match err {
        sqlx::Error::Database(db) => sqlstate_is_feature_not_supported(db.code().as_deref()),
        _ => false,
    }
}

fn sqlstate_is_feature_not_supported(code: Option<&str>) -> bool {
    code == Some(FEATURE_NOT_SUPPORTED)
}

/// The variant and SQLSTATE of a discarded error, for the operator, with
/// where it came from when that is known. Never the error's `Display` (see
/// module docs). The field names are the tool-dispatch span's.
pub(super) fn log_discarded(err: &sqlx::Error, origin: Option<&Origin<'_>>, what: &'static str) {
    tracing::warn!(
        error_kind = error_kind(err),
        sqlstate = sqlstate(err).as_deref().unwrap_or(""),
        request_id = origin
            .and_then(|origin| origin.request_id)
            .map(tracing::field::display),
        server = origin.map(|origin| origin.server),
        db = origin.map(|origin| origin.database),
        "{what}"
    );
}

/// Stable, credential-free name of a `sqlx::Error` variant.
pub(super) fn error_kind(err: &sqlx::Error) -> &'static str {
    match err {
        sqlx::Error::Configuration(_) => "configuration",
        sqlx::Error::Database(_) => "database",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Protocol(_) => "protocol",
        sqlx::Error::RowNotFound => "row_not_found",
        sqlx::Error::TypeNotFound { .. } => "type_not_found",
        sqlx::Error::ColumnIndexOutOfBounds { .. } => "column_index_out_of_bounds",
        sqlx::Error::ColumnNotFound(_) => "column_not_found",
        sqlx::Error::ColumnDecode { .. } => "column_decode",
        sqlx::Error::Decode(_) => "decode",
        sqlx::Error::PoolTimedOut => "pool_timed_out",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::WorkerCrashed => "worker_crashed",
        _ => "other",
    }
}

#[cfg(test)]
mod tests;
