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
