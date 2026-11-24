//! `servers:` validation: each server and each of its databases is checked
//! independently, so one bad entry does not hide the next.

use std::collections::HashSet;

use crate::config::schema::{Database, Server, ServerKind};
use crate::exec::RedisDbIndex;

use super::ConfigFileError;
use super::limits::validate_server_values;
use super::roles::{reject_superuser_role, validate_role};
use super::write_tier::validate_write_role;

/// Returns the declared server names for the grant cross-checks; each
/// server's failures land in `errors`.
pub(super) fn validate_servers<'a>(
    servers: &'a [Server],
    errors: &mut Vec<ConfigFileError>,
) -> HashSet<&'a str> {
    let mut server_names: HashSet<&str> = HashSet::new();
    for server in servers {
        let duplicate = !server_names.insert(&server.name);
        if let Err(err) = validate_server(server, duplicate) {
            errors.push(err);
        }
        validate_databases(server, errors);
    }
    server_names
}

fn validate_server(server: &Server, duplicate: bool) -> Result<(), ConfigFileError> {
    validate_server_values(server)?;
    reject_wildcard_name("server", &server.name)?;
    if duplicate {
        return Err(ConfigFileError::Invalid(format!(
            "duplicate server name `{}`",
            server.name
        )));
    }
    // The lazy `AdapterRegistry` (src/exec/mod.rs) dispatches only postgres,
    // mongo and redis today; a `mysql`/`mssql` target parses, boots clean, then
    // fails every query with `UnsupportedAdapter`. Reject at boot instead —
    // spec 08 "errors at this stage refuse to start". `ServerKind::has_adapter`
    // is the shared source of truth with the registry's dispatch match.
    if !server.kind.has_adapter() {
        return Err(ConfigFileError::Invalid(format!(
            "server `{}` has kind `{:?}`, which has no query adapter yet \
             (supported kinds: postgres, mongo, redis)",
            server.name, server.kind
        )));
    }
    Ok(())
}

fn validate_databases(server: &Server, errors: &mut Vec<ConfigFileError>) {
    let mut db_names: HashSet<&str> = HashSet::new();
    for db in &server.databases {
        let duplicate = !db_names.insert(&db.name);
        if let Err(err) = validate_database(server, db, duplicate) {
            errors.push(err);
        }
    }
}

fn validate_database(
    server: &Server,
    db: &Database,
    duplicate: bool,
) -> Result<(), ConfigFileError> {
    reject_wildcard_name("database", &db.name)?;
    if duplicate {
        return Err(ConfigFileError::Invalid(format!(
            "duplicate database `{}` in server `{}`",
            db.name, server.name
        )));
    }
    // The value is not echoed: a password pasted into `role:` must not reach
    // the boot log.
    if validate_role(&db.role).is_err() {
        return Err(ConfigFileError::Invalid(format!(
            "database `{}` in server `{}`: `role` must match ^[a-zA-Z_][a-zA-Z0-9_]*$",
            db.name, server.name
        )));
    }
    reject_superuser_role(&db.role, server.kind, &db.name, &server.name)?;
    validate_write_role(db, server)?;
    if server.kind == ServerKind::Redis {
        validate_redis_database(db, &server.name)?;
    }
    // `Some("")` would silently override the `None → name` fallback and force
    // mongo to authenticate against an empty `authSource`, surfacing as a
    // cryptic runtime auth failure instead of a boot error. Mirrors the
    // `admin.group` non-empty rule.
    if let Some(auth_db) = &db.auth_database
        && auth_db.trim().is_empty()
    {
        return Err(ConfigFileError::Invalid(format!(
            "database `{}` in server `{}` has empty `auth_database`; \
             omit the field to fall back to `name`, or set a non-blank value",
            db.name, server.name
        )));
    }
    Ok(())
}

/// A Redis database is a logical index: `name` must be its canonical decimal
/// form (`"0"`, not `"00"` or `"+0"`), so one index has one grant address.
/// `auth_database` has no Redis meaning (ACL users are server-wide).
fn validate_redis_database(db: &Database, server_name: &str) -> Result<(), ConfigFileError> {
    if RedisDbIndex::parse(&db.name).is_none() {
        return Err(ConfigFileError::Invalid(format!(
            "database `{}` in redis server `{server_name}` must be a logical database \
             index written as a plain decimal number (e.g. `0`)",
            db.name
        )));
    }
    if db.auth_database.is_some() {
        return Err(ConfigFileError::Invalid(format!(
            "database `{}` in redis server `{server_name}` sets `auth_database`, which \
             redis targets do not use; remove it",
            db.name
        )));
    }
    Ok(())
}

/// `*` is the grant wildcard; a server or database actually named `*` would
/// make `server: "*"` ambiguous between "every server" and "that one".
fn reject_wildcard_name(kind: &str, name: &str) -> Result<(), ConfigFileError> {
    if name.trim() == "*" {
        return Err(ConfigFileError::Invalid(format!(
            "{kind} name `*` is reserved for the grant wildcard; rename the {kind}"
        )));
    }
    Ok(())
}
