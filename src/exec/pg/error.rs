//! `sqlx::Error` → [`ExecError`], and the one log line per discarded error.
//!
//! Nothing here renders an error with `Display`: connect-phase sqlx errors
//! can quote the DSN (`Configuration`) or name the role and host, and the
//! request path never leaks credentials. Logs carry the variant name and the
//! SQLSTATE only; the agent gets the SQLSTATE and the gateway's wording for
//! a statement-level error (see [`super::redact`]) and an opaque code for
//! everything else.

use sqlx::error::DatabaseError;
use sqlx::postgres::{PgDatabaseError, PgErrorPosition};

use super::super::adapter::ExecError;
use super::super::rejection::DbRejection;
use super::super::sql_guard::Access;
use super::redact::rejection_message;

/// Classify an error raised while `sql` ran — the caller's statement, or
/// `""` for one of the gateway's own. `role` is redacted from the message.
pub(super) fn classify(err: sqlx::Error, role: &str, sql: &str) -> ExecError {
    log_discarded(&err, "target statement failed");
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
            // Invalid authorization: a login refusal, whose text names the
            // role and can name the client address. Never passed on, however
            // it got here.
            c if c.starts_with("28") => ExecError::Connection,
            c => {
                let message = rejection_message(c, db.message(), error_position(db.as_ref()), sql);
                ExecError::Rejected(DbRejection::new(c, &message, role))
            }
        };
    }
    if matches!(err, sqlx::Error::PoolTimedOut | sqlx::Error::Io(_)) {
        return ExecError::Unavailable;
    }
    ExecError::Sql
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
    role: &str,
    sql: &str,
) -> ExecError {
    match classify(err, role, sql) {
        ExecError::Unavailable | ExecError::Sql if access == Access::ReadWrite => {
            ExecError::CommitIndeterminate
        }
        other => other,
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
    pub(super) fn of(err: &sqlx::Error) -> Self {
        log_discarded(err, "target connection failed");
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

/// The variant and SQLSTATE of a discarded error, for the operator. Never
/// the error's `Display` (see module docs).
pub(super) fn log_discarded(err: &sqlx::Error, what: &'static str) {
    let sqlstate = match err {
        sqlx::Error::Database(db) => db.code().map(|c| c.into_owned()),
        _ => None,
    };
    tracing::warn!(
        error_kind = error_kind(err),
        sqlstate = sqlstate.as_deref().unwrap_or(""),
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
mod tests {
    use super::*;

    #[test]
    fn pool_and_io_errors_are_unavailable() {
        assert!(matches!(
            classify(sqlx::Error::PoolTimedOut, "app", ""),
            ExecError::Unavailable
        ));
        let io = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        assert!(matches!(
            classify(sqlx::Error::Io(io), "app", ""),
            ExecError::Unavailable
        ));
    }

    #[test]
    fn opaque_errors_stay_opaque() {
        assert!(matches!(
            classify(sqlx::Error::RowNotFound, "app", ""),
            ExecError::Sql
        ));
        assert_eq!(
            AcquireFailure::of(&sqlx::Error::PoolTimedOut),
            AcquireFailure::Other
        );
    }

    fn io_reset() -> sqlx::Error {
        sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
    }

    #[test]
    fn lost_connection_at_write_commit_is_indeterminate() {
        assert!(matches!(
            classify_commit(io_reset(), Access::ReadWrite, "app", ""),
            ExecError::CommitIndeterminate
        ));
        assert!(matches!(
            classify_commit(
                sqlx::Error::Protocol("eof".into()),
                Access::ReadWrite,
                "app",
                ""
            ),
            ExecError::CommitIndeterminate
        ));
    }

    #[test]
    fn lost_connection_at_read_commit_stays_unavailable() {
        assert!(matches!(
            classify_commit(io_reset(), Access::ReadOnly, "app", ""),
            ExecError::Unavailable
        ));
    }

    #[test]
    fn only_sqlstate_0a000_is_feature_not_supported() {
        assert!(sqlstate_is_feature_not_supported(Some("0A000")));
        assert!(!sqlstate_is_feature_not_supported(Some("42501")));
        assert!(!sqlstate_is_feature_not_supported(None));
        assert!(!is_feature_not_supported(&sqlx::Error::PoolTimedOut));
    }
}
