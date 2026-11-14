//! Input validation + error mapping specific to the grants handlers. The
//! cross-entity helpers live in [`super::super::validation`].

use serde_json::{Value as JsonValue, json};

use crate::authz::ConstraintsPatch;
use crate::config::Constraints;
use crate::state::permissions::{GrantAction, GrantTarget, RepoError};

use super::super::error::AdminError;
use super::super::validation::{declared_server, store_error, trimmed_non_empty};
use super::dto::CreateGrantRequest;

/// Parse the request body's target fields into a `GrantTarget`, rejecting
/// every illegal combination the storage XOR CHECK would later catch.
///
/// Legal forms (spec 12 §"Wildcard grants"):
///   - `database_id` set, `server` absent, `db_name_wildcard` absent/false
///     → `GrantTarget::Specific`
///   - `database_id` absent, `server` set, `db_name_wildcard == true`
///     → `GrantTarget::Wildcard`, where `server` must be a server the
///     gateway config declares: `*` is not a server, and a typo would
///     otherwise sit as a dormant grant that a later config change arms.
pub(super) fn parse_grant_target(
    body: &CreateGrantRequest,
    known_servers: &[String],
    request_id: &str,
) -> Result<GrantTarget, AdminError> {
    let wildcard = body.db_name_wildcard.unwrap_or(false);
    match (&body.database_id, &body.server, wildcard) {
        (Some(database_id), None, false) => Ok(GrantTarget::Specific {
            database_id: *database_id,
        }),
        (None, Some(server), true) => {
            let server = trimmed_non_empty(server, "server", request_id)?;
            let server = declared_server(server, known_servers, request_id)?;
            Ok(GrantTarget::Wildcard { server })
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

/// `row_limit` / `statement_timeout_ms` of `0` would disable the call, not
/// bound it (Postgres reads `statement_timeout = 0` as "no timeout"), so a
/// bound, when given, must be positive. Applies to a POST body.
pub(super) fn positive_bounds(c: &Constraints, request_id: &str) -> Result<(), AdminError> {
    reject_zero(c.row_limit, c.statement_timeout_ms, request_id)
}

/// [`positive_bounds`] for the keys a PATCH names; `null` (clear) is fine.
pub(super) fn positive_patch_bounds(
    p: &ConstraintsPatch,
    request_id: &str,
) -> Result<(), AdminError> {
    reject_zero(
        p.row_limit.flatten(),
        p.statement_timeout_ms.flatten(),
        request_id,
    )
}

fn reject_zero(
    row_limit: Option<u32>,
    statement_timeout_ms: Option<u32>,
    request_id: &str,
) -> Result<(), AdminError> {
    for (field, value) in [
        ("row_limit", row_limit),
        ("statement_timeout_ms", statement_timeout_ms),
    ] {
        if value == Some(0) {
            return Err(AdminError::invalid(format!(
                "constraints.{field} must be positive when set"
            ))
            .with_request_id(request_id));
        }
    }
    Ok(())
}

/// The JSONB layout the resolver reads back — identical whether the grant
/// came from a POST or a merged PATCH, so symmetric merge can rely on it.
pub(super) fn constraints_to_json(c: &Constraints) -> JsonValue {
    json!({
        "require_reason": c.require_reason,
        "row_limit": c.row_limit,
        "statement_timeout_ms": c.statement_timeout_ms,
    })
}

/// Map `tx_create_grant` failures so a DB-level CHECK violation comes back
/// as `invalid_request` (400). `23514` covers the XOR target / action CHECKs
/// the handler already pre-validates — belt-and-suspenders for future CHECKs.
/// A dead reference is not an error here: `tx_create_grant` returns `None`.
/// Anything else goes through the redacted [`store_error`].
pub(super) fn map_create_grant_error(err: RepoError, request_id: &str) -> AdminError {
    if let RepoError::Sqlx(sqlx::Error::Database(db_err)) = &err
        && db_err.code().as_deref() == Some("23514")
    {
        return AdminError::invalid("grant violates target/action constraints")
            .with_request_id(request_id);
    }
    store_error("create_grant", err, request_id)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn wildcard_body(server: &str) -> CreateGrantRequest {
        serde_json::from_value(json!({
            "user_id": Uuid::nil(),
            "server": server,
            "db_name_wildcard": true,
            "action": "query_read",
        }))
        .unwrap()
    }

    #[test]
    fn zero_bounds_are_rejected_and_positive_or_absent_pass() {
        let zero_rows = Constraints {
            row_limit: Some(0),
            ..Constraints::default()
        };
        let zero_timeout = Constraints {
            statement_timeout_ms: Some(0),
            ..Constraints::default()
        };
        assert!(positive_bounds(&zero_rows, "r").is_err());
        assert!(positive_bounds(&zero_timeout, "r").is_err());
        assert!(positive_bounds(&Constraints::default(), "r").is_ok());
        let patch = |row_limit| ConstraintsPatch {
            row_limit,
            ..ConstraintsPatch::default()
        };
        assert!(positive_patch_bounds(&patch(Some(Some(0))), "r").is_err());
        assert!(positive_patch_bounds(&patch(Some(None)), "r").is_ok());
        assert!(positive_patch_bounds(&patch(Some(Some(1))), "r").is_ok());
    }

    #[test]
    fn wildcard_on_declared_server_is_accepted() {
        let known = vec!["prod".to_string()];
        let target = parse_grant_target(&wildcard_body(" prod "), &known, "r").unwrap();
        assert_eq!(
            target,
            GrantTarget::Wildcard {
                server: "prod".into()
            }
        );
    }

    #[test]
    fn wildcard_on_star_or_unknown_server_is_rejected() {
        let known = vec!["prod".to_string()];
        for server in ["*", "staging", "", "PROD"] {
            assert!(
                parse_grant_target(&wildcard_body(server), &known, "r").is_err(),
                "{server:?} must be rejected"
            );
        }
    }
}
