//! The write tier: a database's optional `write_role`, and the rule that a
//! `query_write` grant only reaches databases that declare one.
//!
//! Reads always connect as `role`; only a `query_write` grant runs as
//! `write_role`. Keeping the two roles distinct is what makes "the read tier
//! cannot write" a property of the database's own privileges rather than of
//! the SQL guard.

use crate::config::schema::{Action, Database, Permission, Server, ServerKind};

use super::ConfigFileError;
use super::roles::{reject_superuser_role, validate_role};

/// `write_role` and `write_password` come as a pair, on postgres only, and
/// the write role is never the read role.
pub(super) fn validate_write_role(db: &Database, server: &Server) -> Result<(), ConfigFileError> {
    let where_ = || format!("database `{}` in server `{}`", db.name, server.name);
    let role = match (&db.write_role, &db.write_password) {
        (None, None) => return Ok(()),
        (Some(role), Some(_)) => role,
        (Some(_), None) => {
            return Err(invalid(format!(
                "{} sets `write_role` without `write_password`",
                where_()
            )));
        }
        (None, Some(_)) => {
            return Err(invalid(format!(
                "{} sets `write_password` without `write_role`",
                where_()
            )));
        }
    };
    // Mongo writes are out of scope (spec 12): its adapter is read-only, so a
    // write role there would be credentials the gateway never uses.
    if server.kind != ServerKind::Postgres {
        return Err(invalid(format!(
            "{} sets `write_role`, which only postgres targets support",
            where_()
        )));
    }
    validate_role(role).map_err(ConfigFileError::Invalid)?;
    reject_superuser_role(role, server.kind, &db.name, &server.name)?;
    if role == &db.role {
        return Err(invalid(format!(
            "{} uses the same role for `role` and `write_role`; the read role \
             must not hold write privileges — provision a separate read-only role",
            where_()
        )));
    }
    Ok(())
}

/// Every database a `query_write` grant matches must declare a `write_role`,
/// wildcards expanded against the configured databases. Fails boot instead
/// of failing every write at request time.
pub(super) fn validate_write_grants(
    permissions: &[Permission],
    servers: &[Server],
) -> Result<(), ConfigFileError> {
    for permission in permissions {
        for grant in permission
            .grants
            .iter()
            .filter(|g| g.action == Action::QueryWrite)
        {
            let read_only = servers
                .iter()
                .filter(|s| grant.server == "*" || grant.server == s.name)
                .flat_map(|s| s.databases.iter().map(move |d| (s, d)))
                .filter(|(_, d)| grant.database == "*" || grant.database == d.name)
                .find(|(_, d)| d.write_credentials().is_none());
            if let Some((server, db)) = read_only {
                return Err(invalid(format!(
                    "permission group `{}` grants `query_write` on database `{}` of \
                     server `{}`, which has no `write_role`; add `write_role` + \
                     `write_password` or narrow the grant",
                    permission.group, db.name, server.name
                )));
            }
        }
    }
    Ok(())
}

fn invalid(message: String) -> ConfigFileError {
    ConfigFileError::Invalid(message)
}
