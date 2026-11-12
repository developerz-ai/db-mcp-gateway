//! Input validation + error mapping specific to the databases handlers. The
//! cross-entity helpers live in [`super::super::validation`].

use crate::state::permissions::{DbType, RepoError};

use super::super::error::AdminError;
use super::super::validation::store_error;

/// Reject anything outside the `permissions_databases.db_type` CHECK — the
/// target engines (`postgres`, `mysql`, `mongo`). Surfacing it here keeps the
/// error code stable (`invalid_request`) instead of a 500 from the CHECK.
pub(super) fn parse_db_type(value: &str, request_id: &str) -> Result<DbType, AdminError> {
    DbType::parse(value.trim()).map_err(|_| {
        AdminError::invalid(format!(
            "db_type `{value}` not supported (allowed: {})",
            DbType::ALLOWED
        ))
        .with_request_id(request_id)
    })
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
/// the grants handlers, which need no `23505` mapping only because
/// `permissions_grants` has no UNIQUE index — this table does.
///
/// The index is partial, so a soft-deleted pair does not conflict: the
/// same `(server, db_name)` can be registered again after a DELETE.
///
/// We match on `constraint()` too, not just `code()`. Any future UNIQUE
/// index added to `permissions_databases` (e.g. a per-tenant one) would
/// share SQLSTATE `23505` — surfacing "already registered" for a violation
/// on an unrelated constraint would mislead the caller and, worse, leak
/// the existence of an index the API doesn't document. Unknown
/// constraints stay on the redacted `internal` path per spec 12
/// §"Error mapping".
///
/// Anything else goes through the redacted [`store_error`]. The message is
/// built from the caller's own already-validated input, never from the DB
/// error string, which would quote the offending values.
pub(super) fn map_duplicate_database_error(
    err: RepoError,
    stage: &'static str,
    server: &str,
    db_name: &str,
    request_id: &str,
) -> AdminError {
    if let RepoError::Sqlx(sqlx::Error::Database(db_err)) = &err
        && db_err.code().as_deref() == Some("23505")
        && db_err.constraint() == Some("permissions_databases_server_db_name_live_idx")
    {
        return AdminError::invalid(format!(
            "database `{db_name}` on server `{server}` is already registered"
        ))
        .with_request_id(request_id);
    }
    store_error(stage, err, request_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_db_type_accepts_every_target_engine() {
        for (raw, want) in [
            ("postgres", DbType::Postgres),
            (" mysql ", DbType::Mysql),
            ("mongo", DbType::Mongo),
        ] {
            assert_eq!(parse_db_type(raw, "r").unwrap(), want);
        }
        assert!(parse_db_type("sqlite", "r").is_err());
    }
}
