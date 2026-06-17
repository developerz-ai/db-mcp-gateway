//! Input validation + error-mapping helpers shared by the databases handlers.
//!
//! Reject bad input early with the stable admin-error envelope so clients
//! see `invalid_request` + `request_id` instead of Axum's default 400/422.

use crate::state::permissions::DbType;

use super::super::error::AdminError;

pub(super) fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

pub(super) fn invalid_id(request_id: &str) -> AdminError {
    AdminError::invalid("invalid database id").with_request_id(request_id)
}

pub(super) fn trimmed_non_empty(
    value: &str,
    field: &str,
    request_id: &str,
) -> Result<String, AdminError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(AdminError::invalid(format!("{field} must be non-empty")).with_request_id(request_id))
    } else {
        Ok(trimmed.to_string())
    }
}

/// Reject anything outside the `permissions_databases.db_type` CHECK (currently
/// `postgres` | `mysql`). `mongo` is intentionally rejected — spec 12
/// §"Storage backends" excludes mongo from the permissions store; it appears
/// only as a query target (#57–#58). Surfacing the rejection here keeps the
/// error code stable (`invalid_request`) instead of a 500 from the eventual
/// DB CHECK violation.
pub(super) fn parse_db_type(value: &str, request_id: &str) -> Result<DbType, AdminError> {
    DbType::parse(value.trim()).map_err(|_| {
        AdminError::invalid(format!(
            "db_type `{value}` not supported (allowed: postgres, mysql)"
        ))
        .with_request_id(request_id)
    })
}

/// Same logging discipline as [`super::super::users`]: we log `stage` +
/// `error_type` + `request_id` but NEVER the underlying error string. A sqlx
/// error's `Display` impl can quote constraint-violation detail that, on
/// `permissions_databases`, would include the offending `server`/`db_name`
/// values — and could in principle echo back content from a future column
/// we haven't anticipated. CLAUDE.md non-negotiable #1.
pub(super) fn internal<E>(stage: &'static str, _err: E, request_id: &str) -> AdminError {
    let error_type = std::any::type_name::<E>();
    tracing::error!(
        stage,
        error_type,
        %request_id,
        "admin databases endpoint failed"
    );
    AdminError::internal().with_request_id(request_id)
}
