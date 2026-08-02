//! Input validation + error-mapping helpers shared by the databases handlers.
//!
//! Reject bad input early with the stable admin-error envelope so clients
//! see `invalid_request` + `request_id` instead of Axum's default 400/422.

use crate::state::permissions::{DbType, RepoError};

use super::super::error::AdminError;

pub(super) fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

pub(super) fn invalid_id(request_id: &str) -> AdminError {
    AdminError::invalid("invalid database id").with_request_id(request_id)
}

/// Validates `server` and `db_name` on create/patch. Beyond non-empty, the
/// bare string `"*"` is rejected: it's the magic wildcard marker the authz
/// evaluator checks for (`grant.server == "*"` / `grant.database == "*"` —
/// see `authz::mod::can_see_server` / `matches`). A `permissions_databases`
/// row literally named `"*"` would make every `Specific`-target grant
/// pointing at it silently match every database on the server (or, for
/// `server == "*"`, every server on the gateway) — an authz escalation an
/// admin naming a database `"*"` would not expect or intend. The supported
/// way to grant a wildcard is `GrantTarget::Wildcard` via
/// `db_name_wildcard: true` + `database_id: null` on `/admin/v1/grants`,
/// never a literal `db_name`.
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
    if trimmed == "*" {
        return Err(AdminError::invalid(format!(
            "{field} cannot be the literal `*` — that string is reserved for wildcard grants \
             (see db_name_wildcard on /admin/v1/grants)"
        ))
        .with_request_id(request_id));
    }
    Ok(trimmed.to_string())
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

/// Map create/update failures on `permissions_databases` so the one
/// constraint a client can actually trip comes back as `invalid_request`
/// (400) instead of `internal` (500).
///
/// `23505` unique_violation — migration `0004_permissions.sql` has
/// `permissions_databases_server_db_name_live_idx` UNIQUE on
/// `(server, db_name) WHERE deleted_at IS NULL`. Registering a pair that
/// already exists, or renaming one onto another, is caller-correctable
/// input, not a gateway bug (#136). Mirrors
/// [`super::super::grants::validation::map_create_grant_error`], whose
/// "no `23505` mapping" note holds only because `permissions_grants` has
/// no UNIQUE index — this table does.
///
/// The index is partial, so a soft-deleted pair does not conflict: the
/// same `(server, db_name)` can be registered again after a DELETE.
///
/// Anything else (pool exhaustion, encoder bug, …) stays `internal`. The
/// message is built from the caller's own already-validated input, never
/// from the DB error string, which would quote the offending values —
/// same redaction rule as [`internal`] above.
pub(super) fn map_duplicate_database_error(
    err: RepoError,
    stage: &'static str,
    server: &str,
    db_name: &str,
    request_id: &str,
) -> AdminError {
    if let RepoError::Sqlx(sqlx::Error::Database(db_err)) = &err
        && db_err.code().as_deref() == Some("23505")
    {
        return AdminError::invalid(format!(
            "database `{db_name}` on server `{server}` is already registered"
        ))
        .with_request_id(request_id);
    }
    internal(stage, err, request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trimmed_non_empty_accepts_and_trims_ordinary_names() {
        assert_eq!(
            trimmed_non_empty("  prod  ", "server", "req-1").unwrap(),
            "prod"
        );
    }

    #[test]
    fn trimmed_non_empty_rejects_empty_and_whitespace_only() {
        assert!(trimmed_non_empty("", "db_name", "req-1").is_err());
        assert!(trimmed_non_empty("   ", "db_name", "req-1").is_err());
    }

    /// Regression for the #136 audit finding "permissions_databases rows
    /// named `*` become wildcard grants; nothing rejects the sentinel" — a
    /// `server`/`db_name` of exactly `"*"` must be rejected at the admin
    /// API edge, before it ever reaches `permissions_databases` and gets
    /// picked up as a false wildcard by the authz evaluator.
    #[test]
    fn trimmed_non_empty_rejects_bare_wildcard_sentinel() {
        let err = trimmed_non_empty("*", "db_name", "req-1").unwrap_err();
        assert!(format!("{err:?}").contains("reserved for wildcard grants"));
        let err = trimmed_non_empty("*", "server", "req-1").unwrap_err();
        assert!(format!("{err:?}").contains("reserved for wildcard grants"));
    }

    /// Whitespace padding around the sentinel must not slip past the check —
    /// the comparison runs on the already-trimmed value.
    #[test]
    fn trimmed_non_empty_rejects_wildcard_sentinel_with_padding() {
        assert!(trimmed_non_empty("  *  ", "db_name", "req-1").is_err());
    }

    /// A name that merely *contains* `*` (not equal to it) is a legitimate
    /// database name and must NOT be rejected — only the bare sentinel is
    /// magic to the evaluator.
    #[test]
    fn trimmed_non_empty_allows_names_containing_but_not_equal_to_asterisk() {
        assert_eq!(
            trimmed_non_empty("prod-*-shard", "db_name", "req-1").unwrap(),
            "prod-*-shard"
        );
    }
}
