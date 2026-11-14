//! Phase one of the two-phase audit write: the intent row a dispatch commits
//! before it reaches a target database. The `audit_calls` row written after
//! the work is phase two; an intent left without one is reaped as
//! `abandoned` (see [`super::reaper`]).

use sqlx::PgPool;
use uuid::Uuid;

use crate::exec::sql_guard::Access;

use super::{AUDIT_WRITE_TIMEOUT, AuditError};

/// What the dispatch is about to do, recorded before it does it.
#[derive(Debug, Clone, Copy)]
pub struct CallIntent<'a> {
    /// The dispatch's `request_id` — the key the completion row shares.
    pub request_id: Uuid,
    pub user_sub: &'a str,
    pub user_email: &'a str,
    pub tool: &'static str,
    pub server: &'a str,
    pub database: &'a str,
    pub db_type: Option<&'static str>,
    /// Whether the call may write; an abandoned write may have committed.
    pub access: Access,
    /// What the call runs, as the completion row would record it (capped at
    /// [`super::AUDIT_SQL_MAX_BYTES`] on insert), so an `abandoned` row still
    /// says what may have run.
    pub sql: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// The caller's claimed upstream attribution, carried so an `abandoned`
    /// row keeps it (see [`crate::audit::AuditRow::upstream_actor`]).
    pub upstream_actor: Option<&'a str>,
    pub upstream_run_id: Option<&'a str>,
}

/// Commit the intent row, under the same deadline as the completion write.
/// Callers MUST refuse the target call on `Err`.
pub async fn record(pool: &PgPool, intent: &CallIntent<'_>) -> Result<(), AuditError> {
    let write = crate::state::audit::insert_intent(pool, intent);
    match tokio::time::timeout(AUDIT_WRITE_TIMEOUT, write).await {
        Ok(result) => result.map_err(AuditError::Write),
        Err(_) => Err(AuditError::Timeout(AUDIT_WRITE_TIMEOUT)),
    }
}

/// Appended to the `error_message` of a write-access call whose outcome is
/// unknown (`timeout`, `cancelled`): the statement may have committed before
/// the gateway stopped waiting. This wording is the timeout/cancelled note;
/// the reaper's `abandoned` row words it differently — `no completion
/// recorded before the gateway stopped (access: …)` — but records the same
/// access, so `access: write` there signals the same uncertainty.
pub const WRITE_MAY_HAVE_COMMITTED: &str = "access: write; the statement may have committed";

/// The access the intent of `request_id` recorded, under the audit write
/// deadline. `None` when no intent was committed: the call never reached the
/// target.
pub async fn access_of(pool: &PgPool, request_id: &str) -> Result<Option<Access>, AuditError> {
    let read = crate::state::audit::select_intent_access(pool, request_id);
    match tokio::time::timeout(AUDIT_WRITE_TIMEOUT, read).await {
        Ok(result) => result.map_err(AuditError::Write),
        Err(_) => Err(AuditError::Timeout(AUDIT_WRITE_TIMEOUT)),
    }
}
