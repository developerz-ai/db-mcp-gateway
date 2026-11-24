//! Structural validation run on every parse, one function per YAML section.
//! Sections are checked in file order; later ones cross-reference the names
//! collected by earlier ones.

use std::collections::HashSet;

use crate::config::schema::{Permission, Server, StreamSinkConfig, SyslogTransportKind};

use super::limits::validate_constraint_values;
use super::service_accounts::validate_service_accounts;
use super::targets::validate_servers;
use super::validate_profiles::validate_o13_shapes;
use super::write_tier::validate_write_grants;
use super::{
    AdminConfig, ConfigFile, ConfigFileError, PermissionsStoreBlock, PermissionsStoreDriver,
};

impl ConfigFile {
    /// Every failure at once ([`ConfigFileError::Many`] past one), so an
    /// operator fixes a config in one pass instead of one boot per mistake.
    pub(super) fn validate(&self) -> Result<(), ConfigFileError> {
        ConfigFileError::from_errors(self.validation_errors()).map_or(Ok(()), Err)
    }

    /// Sections, servers, databases and sinks are checked independently; a
    /// section's own rules still stop at its first failure.
    fn validation_errors(&self) -> Vec<ConfigFileError> {
        let admin = &self.admin;
        let mut errors = Vec::new();
        keep_err(
            &mut errors,
            validate_permissions_store(self.permissions_store.as_ref(), admin),
        );
        let server_names = validate_servers(&self.servers, &mut errors);
        let group_names = validate_permissions(&self.permissions, &self.servers, &server_names)
            .unwrap_or_else(|err| {
                errors.push(err);
                self.permissions
                    .iter()
                    .filter_map(Permission::group)
                    .collect()
            });
        keep_err(
            &mut errors,
            validate_o13_shapes(&self.permissions, &self.servers),
        );
        keep_err(
            &mut errors,
            validate_write_grants(&self.permissions, &self.servers),
        );
        keep_err(
            &mut errors,
            validate_service_accounts(&self.service_accounts, &group_names, admin),
        );
        validate_stream_sinks(&self.logging.stream, &mut errors);
        keep_err(&mut errors, self.reject_production_literals());
        errors
    }
}

fn keep_err(errors: &mut Vec<ConfigFileError>, result: Result<(), ConfigFileError>) {
    if let Err(err) = result {
        errors.push(err);
    }
}

/// The admin API writes the store, so it needs one it can write: #59 wires
/// mysql for the resolver hot path only (the admin handlers use raw pg
/// `RETURNING` + `JSONB`), and a YAML-only install has no store at all. Boot
/// fails fast rather than running with a half-wired admin surface.
fn validate_permissions_store(
    store: Option<&PermissionsStoreBlock>,
    admin: &AdminConfig,
) -> Result<(), ConfigFileError> {
    let Some(store) = store else {
        return Ok(());
    };
    if !matches!(admin, AdminConfig::Enabled { .. }) {
        return Ok(());
    }
    match store.driver {
        PermissionsStoreDriver::Pg => Ok(()),
        PermissionsStoreDriver::Mysql => Err(ConfigFileError::Invalid(
            "permissions_store.driver = mysql is not supported with admin.enabled = true. \
             #59 wires mysql for the resolver hot path only; full admin parity is tracked \
             in a future issue. Either set admin.enabled = false or use driver = pg."
                .to_string(),
        )),
        PermissionsStoreDriver::YamlOnly => Err(ConfigFileError::Invalid(
            "permissions_store.driver = none (YAML-only) is not supported with \
             admin.enabled = true: the admin API edits the permissions store, which a \
             YAML-only install does not have. Set admin.enabled = false or use driver = pg."
                .to_string(),
        )),
    }
}

/// Returns the declared permission group names for the service-account checks.
/// `user:` blocks are checked in `validate_profiles` and declare no group.
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
        if let Some(group) = permission.group() {
            if group.trim().is_empty() {
                return Err(ConfigFileError::Invalid(
                    "permission group name must be non-empty".to_string(),
                ));
            }
            if !group_names.insert(group) {
                return Err(ConfigFileError::Invalid(format!(
                    "duplicate permission group `{group}`"
                )));
            }
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
                "permission {} has a grant with an empty `server`",
                permission.subject
            )));
        }
        if grant.database.trim().is_empty() {
            return Err(ConfigFileError::Invalid(format!(
                "permission {} has a grant with an empty `database`",
                permission.subject
            )));
        }
        if grant.server != "*" && !server_names.contains(grant.server.as_str()) {
            return Err(ConfigFileError::Invalid(format!(
                "permission {} grants on unknown server `{}`",
                permission.subject, grant.server
            )));
        }
        if grant.database != "*" && !grant_database_exists(servers, &grant.server, &grant.database)
        {
            return Err(ConfigFileError::Invalid(format!(
                "permission {} grants on unknown database `{}` of server `{}`",
                permission.subject, grant.database, grant.server
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
fn validate_stream_sinks(sinks: &[StreamSinkConfig], errors: &mut Vec<ConfigFileError>) {
    for (index, sink) in sinks.iter().enumerate() {
        keep_err(errors, validate_stream_sink(index, sink));
    }
}

fn validate_stream_sink(index: usize, sink: &StreamSinkConfig) -> Result<(), ConfigFileError> {
    let StreamSinkConfig::Syslog {
        host,
        port,
        transport,
        ca_file,
    } = sink
    else {
        return Ok(());
    };
    if host.trim().is_empty() {
        return Err(ConfigFileError::SyslogSinkBlankHost { index });
    }
    if *port == 0 {
        return Err(ConfigFileError::SyslogSinkZeroPort { index });
    }
    match (transport, ca_file) {
        (SyslogTransportKind::Tls, None) => {
            Err(ConfigFileError::SyslogSinkTlsNeedsCaFile { index })
        }
        (SyslogTransportKind::Udp | SyslogTransportKind::Tcp, Some(_)) => {
            Err(ConfigFileError::SyslogSinkCaFileWithoutTls { index })
        }
        _ => Ok(()),
    }
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
