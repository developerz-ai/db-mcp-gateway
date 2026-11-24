//! `servers:` — the targets the gateway connects to, and the per-database
//! read and write roles it connects as.

use std::path::PathBuf;

use serde::Deserialize;

use super::super::pool::PoolConfig;
use super::super::secret::Password;
use super::database::{DatabaseDefaults, DatabaseEntry};

pub use super::database::Database;

/// Deserialized through [`ServerSpec`], so an omitted `port` resolves to the
/// kind's own default ([`ServerKind::default_port`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "ServerSpec")]
pub struct Server {
    pub name: String,
    pub kind: ServerKind,
    /// Human-readable purpose. Surfaced to agents via `list_servers`.
    pub description: String,
    pub host: String,
    pub port: u16,
    pub tls: Tls,
    /// CA bundle (PEM) for `tls: verify_full`; absent → system roots. Rejected
    /// at boot unless `tls: verify_full`, and must be readable.
    pub tls_ca_file: Option<PathBuf>,
    /// Pool sizing for every database on this server; a database's own
    /// `pool:` wins per field.
    pub pool: Option<PoolConfig>,
    pub databases: Vec<Database>,
}

/// The `servers:` entry as written. `deny_unknown_fields` turns a misspelled
/// key (e.g. `databasses:` instead of `databases:`) into a boot-time error
/// pointing at the line, instead of silently dropping the value — see issue
/// #16. `ConfigFile` and every other section deny unknown keys too.
/// `RawConfigFile` converts these itself so a resolution error keeps its
/// message (a parse error drops it — it could quote the file).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServerSpec {
    name: String,
    kind: ServerKind,
    #[serde(default)]
    description: String,
    host: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    tls: Tls,
    #[serde(default)]
    tls_ca_file: Option<PathBuf>,
    #[serde(default)]
    pool: Option<PoolConfig>,
    /// Default read role for every database entry that names none.
    #[serde(default)]
    role: Option<String>,
    /// Default password for `role`, same reference rules as a database's.
    #[serde(default)]
    password: Option<Password>,
    #[serde(default)]
    databases: Vec<DatabaseEntry>,
}

impl TryFrom<ServerSpec> for Server {
    type Error = String;

    fn try_from(spec: ServerSpec) -> Result<Self, String> {
        let defaults = DatabaseDefaults {
            server: &spec.name,
            role: spec.role.as_deref(),
            password: spec.password.as_ref(),
        };
        let databases = spec
            .databases
            .into_iter()
            .map(|entry| entry.resolve(defaults))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            port: spec.port.unwrap_or_else(|| spec.kind.default_port()),
            name: spec.name,
            kind: spec.kind,
            description: spec.description,
            host: spec.host,
            tls: spec.tls,
            tls_ca_file: spec.tls_ca_file,
            pool: spec.pool,
            databases,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerKind {
    Postgres,
    Mysql,
    Mssql,
    /// Document-store target — wired in #57. Permissions/storage backends
    /// are still pg-or-mysql only (spec 12 §"Storage backends" excludes
    /// mongo); `Mongo` here is exclusively a *query target* kind, dispatched
    /// to `MongoAdapter` by [`crate::exec::AdapterRegistry`].
    Mongo,
    /// RESP key-value target (Redis, Dragonfly, Valkey, KeyDB), read-only,
    /// dispatched to `RedisAdapter`. `databases[].name` is the numeric
    /// logical database index (`"0"`, `"1"`, …).
    Redis,
}

impl ServerKind {
    /// Whether a query adapter is wired for this kind today. Mirrors the
    /// dispatch in [`crate::exec::AdapterRegistry::get_or_open`]: config
    /// validation rejects servers whose kind returns `false` at boot, so the
    /// registry's `UnsupportedAdapter` arm is a defense-in-depth backstop a
    /// validated config never reaches. Keep the two in sync — `mysql`/`mssql`
    /// flip to `true` only when their adapters land (roadmap §"More adapters").
    ///
    /// Exhaustive on purpose: a new variant must declare its dispatchability
    /// here rather than silently inheriting "supported".
    pub fn has_adapter(self) -> bool {
        match self {
            ServerKind::Postgres | ServerKind::Mongo | ServerKind::Redis => true,
            ServerKind::Mysql | ServerKind::Mssql => false,
        }
    }

    /// The port an omitted `port:` means. Every kind kept 5432 before Redis
    /// landed; only Redis has its own (6379), so existing configs are
    /// unchanged.
    pub fn default_port(self) -> u16 {
        match self {
            ServerKind::Redis => 6379,
            ServerKind::Postgres | ServerKind::Mysql | ServerKind::Mssql | ServerKind::Mongo => {
                5432
            }
        }
    }
}

/// Copy on purpose: callers match it by value. The CA path for
/// `VerifyFull` lives beside it as `Server::tls_ca_file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Tls {
    /// Encrypt. Postgres does not verify the server certificate
    /// (`sslmode=require`) and boot warns per server; Mongo verifies.
    #[default]
    Required,
    /// Encrypt and verify chain + hostname (Postgres `sslmode=verify-full`).
    VerifyFull,
    /// Plaintext. Boot logs a warning per server.
    Insecure,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatchable set must match `exec::AdapterRegistry::get_or_open`.
    /// Pin it here so flipping a kind's support is a deliberate, reviewed edit.
    #[test]
    fn has_adapter_matches_wired_dispatch() {
        assert!(ServerKind::Postgres.has_adapter());
        assert!(ServerKind::Mongo.has_adapter());
        assert!(ServerKind::Redis.has_adapter());
        assert!(!ServerKind::Mysql.has_adapter());
        assert!(!ServerKind::Mssql.has_adapter());
    }

    #[test]
    fn server_defaults_apply() {
        let yaml = r#"
            name: dev
            kind: postgres
            host: localhost
        "#;
        // Production options, not `from_str`'s defaults — a test that parses a
        // config type should exercise the parser the gateway actually boots
        // with, and this keeps `with_snippet: false` the only configuration
        // any config YAML is ever parsed under.
        let server: Server =
            serde_saphyr::from_str_with_options(yaml, crate::config::yaml::non_leaking_options())
                .unwrap();
        assert_eq!(server.port, 5432);
        assert_eq!(server.tls, Tls::Required);
        assert!(server.databases.is_empty());
    }

    fn parse_server(yaml: &str) -> Result<Server, serde_saphyr::Error> {
        serde_saphyr::from_str_with_options(yaml, crate::config::yaml::non_leaking_options())
    }

    /// An omitted port is the kind's own default; an explicit one always wins.
    #[test]
    fn redis_defaults_to_6379_and_an_explicit_port_wins() {
        let server = parse_server("name: cache\nkind: redis\nhost: localhost\n").unwrap();
        assert_eq!(server.kind, ServerKind::Redis);
        assert_eq!(server.port, 6379);
        let server = parse_server("name: c\nkind: redis\nhost: h\nport: 6380\n").unwrap();
        assert_eq!(server.port, 6380);
        let server = parse_server("name: m\nkind: mongo\nhost: h\n").unwrap();
        assert_eq!(
            server.port, 5432,
            "other kinds keep their historical default"
        );
    }

    /// Routing through `ServerSpec` must keep the typo guard (#16).
    #[test]
    fn unknown_server_keys_are_still_rejected() {
        assert!(parse_server("name: c\nkind: redis\nhost: h\nprot: 1\n").is_err());
    }
}
