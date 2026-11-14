//! Structural validation run on every parse, one function per YAML section.
//! Sections are checked in file order; later ones cross-reference the names
//! collected by earlier ones.

use std::collections::HashSet;

use crate::config::schema::{Permission, Server, StreamSinkConfig};

use super::limits::{validate_constraint_values, validate_server_values};
use super::roles::{reject_superuser_role, validate_role};
use super::service_accounts::validate_service_accounts;
use super::write_tier::{validate_write_grants, validate_write_role};
use super::{
    AdminBlock, ConfigFile, ConfigFileError, PermissionsStoreBlock, PermissionsStoreDriver,
};

impl ConfigFile {
    pub(super) fn validate(&self) -> Result<(), ConfigFileError> {
        let admin = self.admin.as_ref();
        validate_admin(admin)?;
        validate_permissions_store(self.permissions_store.as_ref(), admin)?;
        let server_names = validate_servers(&self.servers)?;
        let group_names = validate_permissions(&self.permissions, &self.servers, &server_names)?;
        validate_write_grants(&self.permissions, &self.servers)?;
        validate_service_accounts(&self.service_accounts, &group_names, admin)?;
        validate_stream_sinks(&self.logging.stream)?;
        self.reject_production_literals()
    }
}

fn validate_admin(admin: Option<&AdminBlock>) -> Result<(), ConfigFileError> {
    if let Some(admin) = admin
        && admin.enabled
        && admin.group.trim().is_empty()
    {
        return Err(ConfigFileError::Invalid(
            "admin.group must be non-empty when admin.enabled is true".to_string(),
        ));
    }
    Ok(())
}

/// #59 scope: mysql is wired for the resolver hot path only. The admin
/// handlers use raw pg `RETURNING` + `JSONB` operations that haven't been
/// ported. Boot fails fast rather than running with a half-wired admin surface.
fn validate_permissions_store(
    store: Option<&PermissionsStoreBlock>,
    admin: Option<&AdminBlock>,
) -> Result<(), ConfigFileError> {
    if let (Some(store), Some(admin)) = (store, admin)
        && store.driver == PermissionsStoreDriver::Mysql
        && admin.enabled
    {
        return Err(ConfigFileError::Invalid(
            "permissions_store.driver = mysql is not supported with admin.enabled = true. \
             #59 wires mysql for the resolver hot path only; full admin parity is tracked \
             in a future issue. Either set admin.enabled = false or use driver = pg."
                .to_string(),
        ));
    }
    Ok(())
}

/// Returns the declared server names for the grant cross-checks.
fn validate_servers(servers: &[Server]) -> Result<HashSet<&str>, ConfigFileError> {
    let mut server_names: HashSet<&str> = HashSet::new();
    for server in servers {
        validate_server_values(server)?;
        reject_wildcard_name("server", &server.name)?;
        if !server_names.insert(&server.name) {
            return Err(ConfigFileError::Invalid(format!(
                "duplicate server name `{}`",
                server.name
            )));
        }
        // The lazy `AdapterRegistry` (src/exec/mod.rs) dispatches only
        // postgres + mongo today; a `mysql`/`mssql` target parses, boots
        // clean, then fails every query with `UnsupportedAdapter`. Reject
        // at boot instead — spec 08 "errors at this stage refuse to start".
        // `ServerKind::has_adapter` is the shared source of truth with the
        // registry's dispatch match.
        if !server.kind.has_adapter() {
            return Err(ConfigFileError::Invalid(format!(
                "server `{}` has kind `{:?}`, which has no query adapter yet \
                 (supported kinds: postgres, mongo)",
                server.name, server.kind
            )));
        }
        validate_databases(server)?;
    }
    Ok(server_names)
}

fn validate_databases(server: &Server) -> Result<(), ConfigFileError> {
    let mut db_names: HashSet<&str> = HashSet::new();
    for db in &server.databases {
        reject_wildcard_name("database", &db.name)?;
        if !db_names.insert(&db.name) {
            return Err(ConfigFileError::Invalid(format!(
                "duplicate database `{}` in server `{}`",
                db.name, server.name
            )));
        }
        validate_role(&db.role).map_err(ConfigFileError::Invalid)?;
        reject_superuser_role(&db.role, server.kind, &db.name, &server.name)?;
        validate_write_role(db, server)?;
        // `Some("")` would silently override the `None → name` fallback
        // and force mongo to authenticate against an empty `authSource`,
        // surfacing as a cryptic runtime auth failure instead of a boot
        // error. Mirrors the `admin.group` non-empty rule — every
        // optional-string field that *means something when present*
        // gets the same trim check.
        if let Some(auth_db) = &db.auth_database
            && auth_db.trim().is_empty()
        {
            return Err(ConfigFileError::Invalid(format!(
                "database `{}` in server `{}` has empty `auth_database`; \
                 omit the field to fall back to `name`, or set a non-blank value",
                db.name, server.name
            )));
        }
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

/// Returns the declared permission group names for the service-account checks.
fn validate_permissions<'a>(
    permissions: &'a [Permission],
    servers: &[Server],
    server_names: &HashSet<&str>,
) -> Result<HashSet<&'a str>, ConfigFileError> {
    let mut group_names: HashSet<&str> = HashSet::new();
    for permission in permissions {
        // An empty/whitespace group name would silently grant this block to
        // any identity carrying a blank group claim. Same meaning-when-present
        // rule as `admin.group` and `auth_database` — reject at boot.
        if permission.group.trim().is_empty() {
            return Err(ConfigFileError::Invalid(
                "permission group name must be non-empty".to_string(),
            ));
        }
        if !group_names.insert(&permission.group) {
            return Err(ConfigFileError::Invalid(format!(
                "duplicate permission group `{}`",
                permission.group
            )));
        }
        validate_grants(permission, servers, server_names)?;
        validate_constraint_values(permission)?;
    }
    Ok(group_names)
}

fn validate_grants(
    permission: &Permission,
    servers: &[Server],
    server_names: &HashSet<&str>,
) -> Result<(), ConfigFileError> {
    for grant in &permission.grants {
        // Empty/whitespace `server`/`database` would otherwise surface as
        // a cryptic "unknown server ``" from the existence checks below;
        // reject up front for a clear boot error. (`*` is the wildcard.)
        if grant.server.trim().is_empty() {
            return Err(ConfigFileError::Invalid(format!(
                "permission group `{}` has a grant with an empty `server`",
                permission.group
            )));
        }
        if grant.database.trim().is_empty() {
            return Err(ConfigFileError::Invalid(format!(
                "permission group `{}` has a grant with an empty `database`",
                permission.group
            )));
        }
        if grant.server != "*" && !server_names.contains(grant.server.as_str()) {
            return Err(ConfigFileError::Invalid(format!(
                "permission group `{}` grants on unknown server `{}`",
                permission.group, grant.server
            )));
        }
        if grant.database != "*" && !grant_database_exists(servers, &grant.server, &grant.database)
        {
            return Err(ConfigFileError::Invalid(format!(
                "permission group `{}` grants on unknown database `{}` of server `{}`",
                permission.group, grant.database, grant.server
            )));
        }
    }
    Ok(())
}

/// Stream sinks that touch the network need per-variant boot validation so a
/// typo/omission fails at startup rather than as a silent drop inside the
/// detached delivery task. `stdout` is a local `tracing` emission with no
/// config surface, so nothing to validate for it.
///
/// Failures land as typed variants (`SyslogSinkBlankHost`,
/// `SyslogSinkZeroPort`) rather than free-text `Invalid`, so callers can
/// distinguish "blank host" from "port 0" without parsing text.
fn validate_stream_sinks(sinks: &[StreamSinkConfig]) -> Result<(), ConfigFileError> {
    for (index, sink) in sinks.iter().enumerate() {
        match sink {
            StreamSinkConfig::Stdout => {}
            StreamSinkConfig::Syslog { host, port } => {
                if host.trim().is_empty() {
                    return Err(ConfigFileError::SyslogSinkBlankHost { index });
                }
                if *port == 0 {
                    return Err(ConfigFileError::SyslogSinkZeroPort { index });
                }
            }
        }
    }
    Ok(())
}

fn grant_database_exists(servers: &[Server], server_name: &str, db_name: &str) -> bool {
    // Wildcard server still requires the database name to exist somewhere —
    // otherwise typos like `database: app-typo` are accepted silently and
    // surface only as cryptic runtime auth misses.
    if server_name == "*" {
        return servers
            .iter()
            .any(|s| s.databases.iter().any(|d| d.name == db_name));
    }
    servers
        .iter()
        .find(|s| s.name == server_name)
        .map(|s| s.databases.iter().any(|d| d.name == db_name))
        .unwrap_or(false)
}
