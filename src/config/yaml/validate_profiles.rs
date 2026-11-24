//! Boot checks for the plan-101 O13 config shapes: `user:` permission
//! subjects, `except:` on wildcard grants, and `connect_name`. (Constraint
//! profiles are resolved — and an unknown name rejected — at parse time,
//! `schema::apply_constraint_profiles`.)

use std::collections::HashSet;

use crate::config::schema::{Grant, Permission, Server, ServerKind, Subject};

use super::ConfigFileError;

pub(super) fn validate_o13_shapes(
    permissions: &[Permission],
    servers: &[Server],
) -> Result<(), ConfigFileError> {
    validate_user_subjects(permissions)?;
    for permission in permissions {
        for grant in &permission.grants {
            validate_except(&permission.subject, grant, servers)?;
        }
    }
    servers.iter().try_for_each(validate_connect_names)
}

/// A blank `user:` would match nobody (an SSO `sub` is never empty); two
/// blocks for one subject would split what an operator reads as one grant set.
fn validate_user_subjects(permissions: &[Permission]) -> Result<(), ConfigFileError> {
    let mut seen: HashSet<&str> = HashSet::new();
    for permission in permissions {
        let Subject::User(sub) = &permission.subject else {
            continue;
        };
        if sub.trim().is_empty() {
            return Err(invalid(
                "permission `user:` subject must be non-empty".into(),
            ));
        }
        if !seen.insert(sub) {
            return Err(invalid(format!("duplicate permission user `{sub}`")));
        }
    }
    Ok(())
}

/// `except:` narrows a `database: "*"` grant; on a named database it means
/// nothing. Every entry must name a declared database, so a typo cannot leave
/// the database it meant to exclude covered.
fn validate_except(
    subject: &Subject,
    grant: &Grant,
    servers: &[Server],
) -> Result<(), ConfigFileError> {
    if grant.except.is_empty() {
        return Ok(());
    }
    if grant.database != "*" {
        return Err(invalid(format!(
            "permission {subject} grant on `{}`/`{}` sets `except:`, which only applies \
             to `database: \"*\"`",
            grant.server, grant.database
        )));
    }
    for name in &grant.except {
        let declared = servers
            .iter()
            .filter(|s| grant.server == "*" || grant.server == s.name)
            .any(|s| s.databases.iter().any(|d| d.name == *name));
        if !declared {
            return Err(invalid(format!(
                "permission {subject} grant on `{}` excepts unknown database `{name}`",
                grant.server
            )));
        }
    }
    Ok(())
}

/// A blank `connect_name` would connect to the server's default database; a
/// Redis database is addressed by its index `name`, so it has none.
fn validate_connect_names(server: &Server) -> Result<(), ConfigFileError> {
    for db in &server.databases {
        let Some(connect_name) = &db.connect_name else {
            continue;
        };
        if server.kind == ServerKind::Redis {
            return Err(invalid(format!(
                "database `{}` in redis server `{}` sets `connect_name`; a redis database \
                 is addressed by its index `name` — remove it",
                db.name, server.name
            )));
        }
        if connect_name.trim().is_empty() {
            return Err(invalid(format!(
                "database `{}` in server `{}` has empty `connect_name`; omit it to connect \
                 to `name`",
                db.name, server.name
            )));
        }
    }
    Ok(())
}

fn invalid(message: String) -> ConfigFileError {
    ConfigFileError::Invalid(message)
}
