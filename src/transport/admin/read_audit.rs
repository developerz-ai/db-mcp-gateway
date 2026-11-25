//! The `audit_calls` row every admin *read* that discloses grants or audit
//! history writes before its response leaves — explain, export, diff and the
//! audit-call stream. Writes audit `permissions_audit` instead
//! ([`super::audited_tx`]). Synchronous: no row, no response (MUST #4).

use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::{self, AuditRow, OutcomeCode};
use crate::tools::audit_dispatch::failure_hold::{FailedAuditWrite, audit_failures};

use super::error::AdminError;
use super::middleware::AdminActor;

/// `audit_calls.tool` of each audited admin read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdminRead {
    Explain,
    Export,
    Diff,
    AuditCalls,
}

impl AdminRead {
    pub(super) fn tool(self) -> &'static str {
        match self {
            Self::Explain => "admin.explain",
            Self::Export => "admin.permissions_export",
            Self::Diff => "admin.permissions_diff",
            Self::AuditCalls => "admin.audit_calls",
        }
    }
}

/// What one read touched, for the row's `server` / `database` / `row_count`.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct ReadScope<'a> {
    pub server: Option<&'a str>,
    pub database: Option<&'a str>,
    pub row_count: Option<i64>,
    /// What the caller asked for (filters, disclosure flags), stored in the
    /// row's `params` so two reads of one scope stay distinguishable.
    pub request: Option<&'a serde_json::Value>,
}

pub(super) async fn audit_read(
    pool: &PgPool,
    actor: &AdminActor,
    read: AdminRead,
    scope: ReadScope<'_>,
) -> Result<(), AdminError> {
    let row = AuditRow {
        id: Uuid::new_v4(),
        request_id: actor.request_id.clone(),
        user_sub: actor.sub.clone(),
        user_email: actor.email.clone(),
        groups: actor.groups.clone(),
        tool: read.tool().to_string(),
        server: scope.server.map(str::to_string),
        database: scope.database.map(str::to_string),
        sql: None,
        params: scope.request.cloned(),
        reason: None,
        outcome: OutcomeCode::Success,
        elapsed_ms: None,
        row_count: scope.row_count,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: None,
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    };
    audit::log(pool, &row).await.map_err(|err| {
        audit_failures().mark(FailedAuditWrite::Write);
        tracing::error!(
            tool = read.tool(),
            cause = %err.class(),
            request_id = %actor.request_id,
            "admin read refused: audit write failed"
        );
        AdminError::audit_unavailable().with_request_id(actor.request_id.as_str())
    })
}
