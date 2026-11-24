//! [`Fingerprint`]: the connection settings an adapter was opened from,
//! reduced to a keyed hash so a slot can tell whether a caller's config
//! snapshot is the one its adapter was built from.

use std::hash::{BuildHasher, Hash, Hasher, RandomState};

use secrecy::ExposeSecret;

use crate::config::{Database, Password, Server};

/// Keyed per process (`RandomState`), so the value says nothing about the
/// password it covers and is never printed or persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Fingerprint(u64);

impl Fingerprint {
    /// Every setting a pool is opened from, write tier included.
    pub(super) fn of(keys: &RandomState, server: &Server, database: &Database) -> Self {
        let mut hasher = keys.build_hasher();
        // Plain-data config enums: their `Debug` is their full value.
        format!(
            "{:?}|{:?}|{:?}|{:?}",
            server.kind, server.tls, server.pool, database.pool
        )
        .hash(&mut hasher);
        server.host.hash(&mut hasher);
        server.port.hash(&mut hasher);
        server.tls_ca_file.hash(&mut hasher);
        database.role.hash(&mut hasher);
        database.auth_database.hash(&mut hasher);
        hash_password(Some(&database.password), &mut hasher);
        database.write_role.hash(&mut hasher);
        hash_password(database.write_password.as_ref(), &mut hasher);
        Self(hasher.finish())
    }
}

/// A literal is hashed by value: `Password`'s `Debug` redacts it, so two
/// different literals would otherwise look the same.
fn hash_password(password: Option<&Password>, hasher: &mut impl Hasher) {
    match password {
        None => 0u8.hash(hasher),
        Some(Password::Literal(secret)) => {
            1u8.hash(hasher);
            secret.expose_secret().hash(hasher);
        }
        Some(Password::EnvVar(name)) => {
            2u8.hash(hasher);
            name.hash(hasher);
        }
        Some(Password::File(path)) => {
            3u8.hash(hasher);
            path.hash(hasher);
        }
        Some(Password::SecretBackend { scheme, reference }) => {
            4u8.hash(hasher);
            scheme.hash(hasher);
            reference.hash(hasher);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigFile;

    fn target(role: &str, password: &str) -> (Server, Database) {
        let yaml = format!(
            "servers:\n  - name: s\n    kind: postgres\n    host: h\n    databases:\n      - {{ name: d, role: {role}, password: {password} }}\npermissions: []\n"
        );
        let mut config = ConfigFile::from_yaml_str(&yaml).expect("test yaml");
        let mut server = config.servers.remove(0);
        let database = server.databases.remove(0);
        (server, database)
    }

    fn print(keys: &RandomState, role: &str, password: &str) -> Fingerprint {
        let (server, database) = target(role, password);
        Fingerprint::of(keys, &server, &database)
    }

    #[test]
    fn same_settings_same_fingerprint() {
        let keys = RandomState::new();
        assert_eq!(print(&keys, "ro", "a"), print(&keys, "ro", "a"));
    }

    #[test]
    fn role_change_is_a_different_fingerprint() {
        let keys = RandomState::new();
        assert_ne!(print(&keys, "ro", "a"), print(&keys, "rw", "a"));
    }

    #[test]
    fn literal_password_change_is_a_different_fingerprint() {
        let keys = RandomState::new();
        assert_ne!(print(&keys, "ro", "a"), print(&keys, "ro", "b"));
    }

    #[test]
    fn reference_kind_change_is_a_different_fingerprint() {
        let keys = RandomState::new();
        assert_ne!(
            print(&keys, "ro", "\"${ENV:A}\""),
            print(&keys, "ro", "\"${FILE:/A}\"")
        );
    }
}
