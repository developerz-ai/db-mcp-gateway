//! Input validation + error-mapping helpers for the grants handlers.

use serde_json::{Value as JsonValue, json};

use crate::config::Constraints;
use crate::state::permissions::{GrantAction, GrantTarget, PermissionsGrant, RepoError};

use super::super::error::AdminError;
use super::dto::CreateGrantRequest;

pub(super) fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

pub(super) fn invalid_id(request_id: &str) -> AdminError {
    AdminError::invalid("invalid grant id").with_request_id(request_id)
}

/// Parse the request body's target fields into a `GrantTarget`, rejecting
/// every illegal combination the storage XOR CHECK would later catch. Surfaces
/// `invalid_request` instead of a generic 500 from the DB constraint.
///
/// Legal forms (spec 12 §"Wildcard grants"):
///   - `database_id` set, `server` absent, `db_name_wildcard` absent/false
///     → `GrantTarget::Specific`
///   - `database_id` absent, `server` set, `db_name_wildcard == true`
///     → `GrantTarget::Wildcard`
///
/// Anything else (both set, neither set, mismatched flag) → 400.
pub(super) fn parse_grant_target(
    body: &CreateGrantRequest,
    request_id: &str,
) -> Result<GrantTarget, AdminError> {
    let wildcard = body.db_name_wildcard.unwrap_or(false);
    match (&body.database_id, &body.server, wildcard) {
        (Some(database_id), None, false) => Ok(GrantTarget::Specific {
            database_id: *database_id,
        }),
        (None, Some(server), true) => {
            let trimmed = server.trim();
            if trimmed.is_empty() {
                Err(AdminError::invalid("server must be non-empty").with_request_id(request_id))
            } else {
                Ok(GrantTarget::Wildcard {
                    server: trimmed.to_string(),
                })
            }
        }
        _ => Err(AdminError::invalid(
            "must set exactly one target: \
             either `database_id` (specific), \
             or `server` plus `db_name_wildcard: true` (wildcard)",
        )
        .with_request_id(request_id)),
    }
}

pub(super) fn parse_action(value: &str, request_id: &str) -> Result<GrantAction, AdminError> {
    GrantAction::parse(value.trim()).map_err(|_| {
        AdminError::invalid(format!(
            "action `{value}` not supported \
             (allowed: schema_read, query_read, query_write, history_read)"
        ))
        .with_request_id(request_id)
    })
}

pub(super) fn constraints_to_json(c: &Constraints) -> JsonValue {
    // Mirrors the JSONB shape the resolver reads back in #49's loader.
    // Stored in the same layout regardless of whether the original write
    // came from YAML or the admin API — symmetric merge depends on it.
    json!({
        "require_reason": c.require_reason,
        "row_limit": c.row_limit,
        "statement_timeout_ms": c.statement_timeout_ms,
    })
}

/// Audit-payload shape — full grant row after the change, for `before`/`after`.
pub(super) fn grant_payload(g: &PermissionsGrant) -> JsonValue {
    let (database_id, server) = match &g.target {
        GrantTarget::Specific { database_id } => (Some(*database_id), None),
        GrantTarget::Wildcard { server } => (None, Some(server.clone())),
    };
    let wildcard = matches!(&g.target, GrantTarget::Wildcard { .. });
    json!({
        "id": g.id,
        "user_id": g.user_id,
        "database_id": database_id,
        "server": server,
        "db_name_wildcard": wildcard,
        "action": g.action.as_db_str(),
        "constraints": g.constraints,
        "created_at": g.created_at,
        "updated_at": g.updated_at,
    })
}

/// Same logging discipline as [`super::super::users`] and
/// [`super::super::databases`]: we log `stage` + `error_type` + `request_id`
/// but NEVER the underlying error string. A sqlx error's `Display` impl can
/// quote constraint-violation detail that could echo back row content.
/// CLAUDE.md non-negotiable #1.
pub(super) fn internal<E>(stage: &'static str, _err: E, request_id: &str) -> AdminError {
    let error_type = std::any::type_name::<E>();
    tracing::error!(
        stage,
        error_type,
        %request_id,
        "admin grants endpoint failed"
    );
    AdminError::internal().with_request_id(request_id)
}

/// Map [`tx_create_grant`](super::sql::tx_create_grant) failures so DB-level
/// constraint violations come back as stable `invalid_request` (400) instead
/// of `internal` (500). The constraints we care about:
///
/// - `23503` foreign_key_violation — `user_id` or `database_id` references
///   a row that does not exist or has been soft-deleted.
/// - `23514` check_violation — the XOR target / action CHECKs from migration
///   `0004_permissions.sql`. The handler pre-validates both, so this branch
///   is belt-and-suspenders for direct API misuse and future schema CHECKs.
///
/// No `23505` (unique_violation) mapping: `permissions_grants` has no UNIQUE
/// index, so it cannot raise this. Stays in the `_` arm if a future migration
/// adds one — failing closed is fine until we have a stable message for it.
///
/// Anything else (pool exhaustion, encoder bug, etc.) stays `internal`. The
/// error string is intentionally not echoed — same redaction as
/// [`internal`] above.
pub(super) fn map_create_grant_error(err: RepoError, request_id: &str) -> AdminError {
    if let RepoError::Sqlx(sqlx::Error::Database(db_err)) = &err {
        match db_err.code().as_deref() {
            Some("23503") => {
                return AdminError::invalid(
                    "invalid grant reference: user or database does not exist",
                )
                .with_request_id(request_id);
            }
            Some("23514") => {
                return AdminError::invalid("grant violates target/action constraints")
                    .with_request_id(request_id);
            }
            _ => {}
        }
    }
    internal("create_grant", err, request_id)
}
