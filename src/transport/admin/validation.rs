//! Input validation and error mapping shared by every `/admin/v1/*` handler,
//! so the three entity families cannot drift apart on wording or redaction.

use chrono::{DateTime, Utc};

use crate::state::permissions::RepoError;

use super::error::AdminError;

/// A malformed or non-JSON body, surfaced in the stable admin envelope
/// instead of Axum's default 400/422.
pub(super) fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

/// A malformed UUID in `:id`.
pub(super) fn invalid_id(entity: &str, request_id: &str) -> AdminError {
    AdminError::invalid(format!("invalid {entity} id")).with_request_id(request_id)
}

pub(super) fn not_found(request_id: &str) -> AdminError {
    AdminError::not_found().with_request_id(request_id)
}

pub(super) fn trimmed_non_empty(
    value: &str,
    field: &str,
    request_id: &str,
) -> Result<String, AdminError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(
            AdminError::invalid(format!("{field} must be non-empty")).with_request_id(request_id)
        );
    }
    Ok(trimmed.to_string())
}

/// [`trimmed_non_empty`] that also rejects the bare `*`: the authz evaluator
/// treats `*` as "any", so a server or database literally named `*` would
/// turn every grant on it into a wildcard.
pub(super) fn routing_name(
    value: &str,
    field: &str,
    request_id: &str,
) -> Result<String, AdminError> {
    let trimmed = trimmed_non_empty(value, field, request_id)?;
    if trimmed == "*" {
        return Err(AdminError::invalid(format!(
            "{field} cannot be the literal `*` — that string is reserved for wildcard grants \
             (see db_name_wildcard on /admin/v1/grants)"
        ))
        .with_request_id(request_id));
    }
    Ok(trimmed)
}

/// Optimistic-concurrency precondition: when the caller names the
/// `updated_at` it last read, a row changed since then is a 409.
pub(super) fn check_unchanged(
    expected: Option<DateTime<Utc>>,
    actual: DateTime<Utc>,
    request_id: &str,
) -> Result<(), AdminError> {
    match expected {
        Some(expected) if expected != actual => Err(AdminError::conflict(
            "row changed since expected_updated_at; re-read and retry",
        )
        .with_request_id(request_id)),
        _ => Ok(()),
    }
}

/// Map a store failure: a deadlock or serialization abort is a retryable
/// `conflict`; everything else is a redacted `internal`.
pub(super) fn store_error(stage: &'static str, err: RepoError, request_id: &str) -> AdminError {
    if let RepoError::Sqlx(sqlx::Error::Database(db_err)) = &err
        && matches!(db_err.code().as_deref(), Some("40P01" | "40001"))
    {
        return AdminError::conflict("concurrent admin change; retry").with_request_id(request_id);
    }
    internal(stage, err, request_id)
}

/// Build an `internal` admin error and trace the failure.
///
/// Logs only `stage`, `error_type` and `request_id` — never `%err`. A
/// Postgres error's `Display` embeds `detail`/`constraint` text that can
/// quote emails, group names or server/database names. CLAUDE.md MUST #1.
pub(super) fn internal<E>(stage: &'static str, _err: E, request_id: &str) -> AdminError {
    let error_type = std::any::type_name::<E>();
    tracing::error!(stage, error_type, %request_id, "admin endpoint failed");
    AdminError::internal().with_request_id(request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trimmed_non_empty_trims_and_rejects_blank() {
        assert_eq!(trimmed_non_empty("  a  ", "f", "r").unwrap(), "a");
        assert!(trimmed_non_empty("", "f", "r").is_err());
        assert!(trimmed_non_empty(" \t\n", "f", "r").is_err());
    }

    /// Regression for #136: a `server`/`db_name` of exactly `*` (padded or
    /// not) must never reach `permissions_databases`.
    #[test]
    fn routing_name_rejects_bare_wildcard_sentinel() {
        for value in ["*", "  *  "] {
            let err = routing_name(value, "db_name", "r").unwrap_err();
            assert!(format!("{err:?}").contains("reserved for wildcard grants"));
        }
    }

    #[test]
    fn routing_name_allows_names_containing_asterisk() {
        assert_eq!(
            routing_name("prod-*-shard", "db_name", "r").unwrap(),
            "prod-*-shard"
        );
    }

    #[test]
    fn check_unchanged_passes_absent_or_equal_and_rejects_drift() {
        let t = Utc::now();
        assert!(check_unchanged(None, t, "r").is_ok());
        assert!(check_unchanged(Some(t), t, "r").is_ok());
        let err = check_unchanged(Some(t - chrono::Duration::seconds(1)), t, "r").unwrap_err();
        assert!(format!("{err:?}").contains("Conflict"));
    }
}
