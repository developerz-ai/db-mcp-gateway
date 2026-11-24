//! `servers[].databases[]` — one entry per database the gateway exposes, and
//! the role it connects as.
//!
//! An entry is a mapping, or (shorthand) just its name, which then takes its
//! `role:` / `password:` from the server. A mapping may omit them too; the
//! server's value fills in, and a database with neither is a parse error.

use serde::Deserialize;
use serde::de::{self, MapAccess, Visitor};

use super::super::pool::PoolConfig;
use super::super::secret::Password;

#[derive(Debug, Clone)]
pub struct Database {
    /// Logical name: what grants, tools and the audit log call it.
    pub name: String,
    pub role: String,
    pub password: Password,
    pub description: String,
    /// Optional authentication database for backends where the role lives
    /// somewhere other than the target database (mongo's `authSource`).
    /// `None` falls back to [`Self::connect_name`] — the least-privilege
    /// per-db user pattern. Operators set this to `"admin"` when
    /// bootstrapping with the container's root user. Ignored by pg (which
    /// authenticates against the connected database).
    pub auth_database: Option<String>,
    /// The database's real name on the server, when the logical `name`
    /// differs (two environments exposing a same-named database, a name a
    /// grant should not spell). `None` → `name`.
    pub connect_name: Option<String>,
    /// Pool sizing for this database; overrides the server's `pool:` per field.
    /// The write pool (when `write_role` is set) is sized the same.
    pub pool: Option<PoolConfig>,
    /// Role a `query_write` grant runs as. Absent → the database is read-only
    /// through the gateway whatever the grants say: reads always use `role`,
    /// so the read tier can never reach a write-capable role. Set together
    /// with `write_password` (boot-checked); postgres targets only.
    pub write_role: Option<String>,
    pub write_password: Option<Password>,
}

impl Database {
    /// The write role and its password, when both are configured. Boot
    /// validation rejects one without the other.
    pub fn write_credentials(&self) -> Option<(&str, &Password)> {
        match (&self.write_role, &self.write_password) {
            (Some(role), Some(password)) => Some((role, password)),
            _ => None,
        }
    }

    /// The name to connect to on the server.
    pub fn connect_name(&self) -> &str {
        self.connect_name.as_deref().unwrap_or(&self.name)
    }
}

/// Server-level values a database entry inherits when it omits its own.
#[derive(Debug, Clone, Copy)]
pub(super) struct DatabaseDefaults<'a> {
    pub server: &'a str,
    pub role: Option<&'a str>,
    pub password: Option<&'a Password>,
}

/// One `databases:` item as written.
#[derive(Debug)]
pub(super) enum DatabaseEntry {
    Name(String),
    Full(Box<DatabaseSpec>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DatabaseSpec {
    name: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    password: Option<Password>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    auth_database: Option<String>,
    #[serde(default)]
    connect_name: Option<String>,
    #[serde(default)]
    pool: Option<PoolConfig>,
    #[serde(default)]
    write_role: Option<String>,
    #[serde(default)]
    write_password: Option<Password>,
}

impl DatabaseEntry {
    pub(super) fn resolve(self, defaults: DatabaseDefaults<'_>) -> Result<Database, String> {
        let spec = match self {
            Self::Name(name) => DatabaseSpec {
                name,
                role: None,
                password: None,
                description: String::new(),
                auth_database: None,
                connect_name: None,
                pool: None,
                write_role: None,
                write_password: None,
            },
            Self::Full(spec) => *spec,
        };
        let missing = |field: &str| {
            format!(
                "database `{}` in server `{}` has no `{field}`; set it on the database \
                 or as the server's default `{field}:`",
                spec.name, defaults.server
            )
        };
        let role = match spec.role.as_deref().or(defaults.role) {
            Some(role) => role.to_string(),
            None => return Err(missing("role")),
        };
        let password = match spec.password.as_ref().or(defaults.password) {
            Some(password) => password.clone(),
            None => return Err(missing("password")),
        };
        Ok(Database {
            name: spec.name,
            role,
            password,
            description: spec.description,
            auth_database: spec.auth_database,
            connect_name: spec.connect_name,
            pool: spec.pool,
            write_role: spec.write_role,
            write_password: spec.write_password,
        })
    }
}

/// Hand-written so a mapping keeps `DatabaseSpec`'s own errors (unknown
/// key, wrong type) — `#[serde(untagged)]` would flatten every mistake into
/// "did not match any variant".
impl<'de> Deserialize<'de> for DatabaseEntry {
    fn deserialize<D: de::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = DatabaseEntry;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a database name or a database mapping")
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<DatabaseEntry, E> {
                Ok(DatabaseEntry::Name(name.to_string()))
            }

            /// A bare Redis index (`databases: [0, 1]`).
            fn visit_u64<E: de::Error>(self, index: u64) -> Result<DatabaseEntry, E> {
                Ok(DatabaseEntry::Name(index.to_string()))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<DatabaseEntry, A::Error> {
                let spec = DatabaseSpec::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(DatabaseEntry::Full(Box::new(spec)))
            }
        }

        de.deserialize_any(EntryVisitor)
    }
}
