//! `sqlx::Error` → [`ExecError`], and the one log line per discarded error.
//!
//! Nothing here renders an error with `Display`: connect-phase sqlx errors
//! can quote the DSN (`Configuration`) or name the role and host, and the
//! request path never leaks credentials. Logs carry the variant name, the
//! SQLSTATE and the [`Origin`] only; the agent gets the SQLSTATE and the gateway's wording for
//! a statement-level error (see [`super::redact`]) and an opaque code for
//! everything else.

use sqlx::error::DatabaseError;
use sqlx::postgres::{PgDatabaseError, PgErrorPosition};
use uuid::Uuid;

use super::super::adapter::ExecError;
use super::super::rejection::DbRejection;
use super::super::sql_guard::Access;
use super::redact::rejection_message;

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
    if let sqlx::Error::Database(db) = &err
        && let Some(code) = db.code()
    {
        return match code.as_ref() {
            // `statement_timeout` raises `57014` (`query_canceled`).
            "57014" => ExecError::Timeout,
            // Connection exception, operator intervention (backend
            // terminated, server shutting down), insufficient resources:
            // the target, not the statement, is the problem.
            c if c.starts_with("08") || c.starts_with("57P") || c.starts_with("53") => {
                ExecError::Unavailable
            }
            // The statement was sound and the target could not finish it
            // this time; nothing in the SQL is there to fix.
            c if rolled_back_by_the_target(c) => ExecError::Unavailable,
            // Invalid authorization: a login refusal, whose text names the
            // role and can name the client address. Never passed on, however
            // it got here.
            c if c.starts_with("28") => ExecError::Connection,
            c => {
                let message = rejection_message(c, error_position(db.as_ref()), sql);
                ExecError::Rejected(DbRejection::new(c, &message, origin.role))
            }
        };
    }
    if matches!(err, sqlx::Error::PoolTimedOut | sqlx::Error::Io(_)) {
        return ExecError::Unavailable;
    }
    ExecError::Sql
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
/// serialization failure) or a cancel means the transaction rolled back, so
/// it keeps its statement-level classification. Anything else on a write —
/// the link dropped, the reply was unreadable — leaves the commit's fate
/// unknown, which the caller must not report as "nothing happened".
pub(super) fn classify_commit(
    err: sqlx::Error,
    access: Access,
    origin: &Origin<'_>,
    sql: &str,
) -> ExecError {
    let rolled_back = sqlstate(&err).is_some_and(|code| rolled_back_by_the_target(&code));
    match classify(err, origin, sql) {
        ExecError::Unavailable | ExecError::Sql if access == Access::ReadWrite && !rolled_back => {
            ExecError::CommitIndeterminate
        }
        other => other,
    }
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
