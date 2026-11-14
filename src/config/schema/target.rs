//! `servers:` — the targets the gateway connects to, and the per-database
//! read and write roles it connects as.

use std::path::PathBuf;

use serde::Deserialize;

use super::super::pool::PoolConfig;
use super::super::secret::Password;

/// Deserialized through [`ServerSpec`], so an omitted `port` resolves to the
/// kind's own default ([`ServerKind::default_port`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(from = "ServerSpec")]
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerSpec {
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
    #[serde(default)]
    databases: Vec<Database>,
}

impl From<ServerSpec> for Server {
    fn from(spec: ServerSpec) -> Self {
        Self {
            port: spec.port.unwrap_or_else(|| spec.kind.default_port()),
            name: spec.name,
            kind: spec.kind,
            description: spec.description,
            host: spec.host,
            tls: spec.tls,
            tls_ca_file: spec.tls_ca_file,
            pool: spec.pool,
            databases: spec.databases,
        }
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub name: String,
    pub role: String,
    pub password: Password,
    #[serde(default)]
    pub description: String,
    /// Optional authentication database for backends where the role lives
    /// somewhere other than the target database (mongo's `authSource`).
    /// `None` falls back to `name` — the least-privilege per-db user
    /// pattern. Operators set this to `"admin"` when bootstrapping with
    /// the container's root user. Ignored by pg (which authenticates
    /// against the connected database).
    #[serde(default)]
    pub auth_database: Option<String>,
    /// Pool sizing for this database; overrides the server's `pool:` per field.
    /// The write pool (when `write_role` is set) is sized the same.
    #[serde(default)]
    pub pool: Option<PoolConfig>,
    /// Role a `query_write` grant runs as. Absent → the database is read-only
    /// through the gateway whatever the grants say: reads always use `role`,
    /// so the read tier can never reach a write-capable role. Set together
    /// with `write_password` (boot-checked); postgres targets only.
    #[serde(default)]
    pub write_role: Option<String>,
    #[serde(default)]
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
