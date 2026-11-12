//! Zero and blank values that parse cleanly but mean nothing (or something
//! dangerous) at runtime. Rejected at boot with the field named.

use crate::config::schema::{Constraints, Permission, Server, Tls};
use crate::exec::PoolSizing;

use super::ConfigFileError;

/// Blank server/database names and hosts, port 0.
pub(super) fn validate_server_values(server: &Server) -> Result<(), ConfigFileError> {
    if server.name.trim().is_empty() {
        return Err(invalid("server `name` must be non-blank"));
    }
    if server.host.trim().is_empty() {
        return Err(invalid(format!(
            "server `{}` has a blank `host`",
            server.name
        )));
    }
    if server.port == 0 {
        return Err(invalid(format!(
            "server `{}` has `port: 0`, which is not a connectable port",
            server.name
        )));
    }
    validate_target_tls(server)?;
    if server.pool.is_some_and(|pool| pool.min_exceeds_max()) {
        return Err(invalid(format!(
            "server `{}` has `pool.min_connections` above `pool.max_connections`",
            server.name
        )));
    }
    // The merged sizing exec will open with (database → server → default), so
    // a min from one level above a max from another fails boot too.
    for db in &server.databases {
        PoolSizing::resolve(server, db).map_err(|err| {
            invalid(format!(
                "database `{}` in server `{}`: merged {err}",
                db.name, server.name
            ))
        })?;
    }
    if let Some(db) = server.databases.iter().find(|db| db.name.trim().is_empty()) {
        return Err(invalid(format!(
            "server `{}` has a database with a blank `name` (role `{}`)",
            server.name, db.role
        )));
    }
    Ok(())
}

/// `tls_ca_file` only means something under `tls: verify_full`, and an
/// unreadable bundle would fail every connect instead of boot.
fn validate_target_tls(server: &Server) -> Result<(), ConfigFileError> {
    let Some(ca_file) = &server.tls_ca_file else {
        return Ok(());
    };
    if server.tls != Tls::VerifyFull {
        return Err(invalid(format!(
            "server `{}` sets `tls_ca_file` without `tls: verify_full`",
            server.name
        )));
    }
    std::fs::metadata(ca_file).map_err(|source| {
        invalid(format!(
            "server `{}` `tls_ca_file` `{}` is not readable: {source}",
            server.name,
            ca_file.display()
        ))
    })?;
    Ok(())
}

/// `row_limit: 0` returns nothing; `statement_timeout_ms: 0` is "no timeout"
/// to Postgres. Neither is what an operator writing a constraint means.
pub(super) fn validate_constraint_values(permission: &Permission) -> Result<(), ConfigFileError> {
    for grant in &permission.grants {
        let Constraints {
            row_limit,
            statement_timeout_ms,
            ..
        } = &grant.constraints;
        for (field, value) in [
            ("row_limit", row_limit),
            ("statement_timeout_ms", statement_timeout_ms),
        ] {
            if *value == Some(0) {
                return Err(invalid(format!(
                    "permission group `{}` grant on `{}`/`{}` has `{field}: 0`; \
                     omit the constraint or set a positive value",
                    permission.group, grant.server, grant.database
                )));
            }
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ConfigFileError {
    ConfigFileError::Invalid(message.into())
}
