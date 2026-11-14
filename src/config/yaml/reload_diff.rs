//! What a reload changes: target pools to evict, and the boot-fixed settings
//! a reload is not allowed to touch.

use std::collections::{BTreeSet, HashMap};

use crate::config::schema::{Database, Server};
use crate::config::secret::Password;

use super::{AdminConfig, ConfigFile};

impl ConfigFile {
    /// `(server, database)` pairs whose connection settings differ between
    /// `self` (old) and `new`, plus pairs `new` removed. A literal password
    /// cannot be compared without exposing it, so a literal always counts as
    /// changed — evicting an unchanged pool costs one reconnect.
    pub fn changed_databases(&self, new: &ConfigFile) -> Vec<(String, String)> {
        let new_prints: HashMap<(&str, &str), Option<String>> = new
            .servers
            .iter()
            .flat_map(|s| s.databases.iter().map(move |d| (s, d)))
            .map(|(s, d)| ((s.name.as_str(), d.name.as_str()), fingerprint(s, d)))
            .collect();
        self.servers
            .iter()
            .flat_map(|s| s.databases.iter().map(move |d| (s, d)))
            .filter(
                |(s, d)| match new_prints.get(&(s.name.as_str(), d.name.as_str())) {
                    Some(Some(new_print)) => fingerprint(s, d).as_ref() != Some(new_print),
                    Some(None) | None => true,
                },
            )
            .map(|(s, d)| (s.name.clone(), d.name.clone()))
            .collect()
    }

    /// The first boot-fixed setting `new` changes, by name. The admin API's
    /// mount, group and known-server list, and the permissions-store driver,
    /// are wired once at boot; a reload that changes them is refused whole
    /// rather than half-applied.
    pub fn boot_fixed_change(&self, new: &ConfigFile) -> Option<&'static str> {
        let driver = |c: &ConfigFile| c.permissions_store.as_ref().map(|p| p.driver);
        // A set: the admin API checks membership, so reordering `servers:`
        // is not a change.
        let admin_servers = |c: &ConfigFile| -> Option<BTreeSet<String>> {
            matches!(c.admin, AdminConfig::Enabled { .. })
                .then(|| c.servers.iter().map(|s| s.name.clone()).collect())
        };
        if self.admin != new.admin {
            Some("admin")
        } else if driver(self) != driver(new) {
            Some("permissions_store")
        } else if admin_servers(self) != admin_servers(new) {
            Some("servers (names, while the admin API is mounted)")
        } else {
            None
        }
    }
}

/// Everything a pool is opened from, write pool included. `None` for a
/// literal password.
fn fingerprint(server: &Server, db: &Database) -> Option<String> {
    if matches!(db.password, Password::Literal(_))
        || matches!(db.write_password, Some(Password::Literal(_)))
    {
        return None;
    }
    Some(format!(
        "{}|{}|{:?}|{:?}|{:?}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
        server.host,
        server.port,
        server.tls,
        server.tls_ca_file,
        server.pool,
        db.role,
        db.auth_database,
        db.pool,
        db.password,
        db.write_role,
        db.write_password,
    ))
}
