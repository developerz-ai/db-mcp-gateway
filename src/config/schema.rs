//! YAML schema for `servers:` and `permissions:`.
//!
//! `Deserialize`-only by design. A `Server` or `Database` carries a `Password`
//! reference; serializing one to a client response would risk leaking it. All
//! client-facing views are separate, credential-free types (see
//! `tools::list_servers::SafeServerView`).
//!
//! Issue #16 will extend this with the full `gateway:` / `auth:` / `logging:`
//! sections and a richer validator. For #3 we only model what `list_servers`
//! needs plus the authz inputs.

use serde::Deserialize;

use super::secret::Password;

/// `deny_unknown_fields` turns a misspelled key (e.g. `databasses:` instead
/// of `databases:`) into a boot-time error pointing at the line, instead of
/// silently dropping the value — see issue #16. Top-level `ConfigFile` stays
/// lenient because it carries un-modeled `gateway:` / `auth:` / `logging:`
/// sections; strictness there waits for the env→YAML unification.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub name: String,
    pub kind: ServerKind,
    /// Human-readable purpose. Surfaced to agents via `list_servers`.
    #[serde(default)]
    pub description: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub databases: Vec<Database>,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Tls {
    #[default]
    Required,
    /// Logs a warning every minute when used in prod — see spec 08.
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
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub group: String,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub server: String,
    pub database: String,
    pub action: Action,
    /// Per-grant constraints layered on top of the action. Optional in YAML;
    /// `authz::evaluate` merges these most-restrictively across all matching
    /// grants (spec 06 §Evaluation).
    #[serde(default)]
    pub constraints: Constraints,
}

/// Constraints from spec 06. All fields optional — the *absence* of a value
/// means "no constraint from this grant". Merging logic lives in
/// `authz::Constraints` because the spec is clearest about merge in that
/// context (most-restrictive-wins).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    #[serde(default)]
    pub require_reason: bool,
    /// Cap on rows returned to the agent (gateway truncates beyond this).
    #[serde(default)]
    pub row_limit: Option<u32>,
    /// Postgres-side `statement_timeout` for queries executed under this grant.
    #[serde(default)]
    pub statement_timeout_ms: Option<u32>,
}

/// Hierarchical: `query_write` implies `query_read` implies `schema_read`.
/// See `Action::includes` and docs/initial-idea/06-permissions.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    SchemaRead,
    QueryRead,
    QueryWrite,
    HistoryRead,
}

impl Action {
    /// Does a grant of `self` cover a request for `requested`?
    pub fn includes(self, requested: Action) -> bool {
        use Action::*;
        match (self, requested) {
            (QueryWrite, _) => matches!(requested, QueryWrite | QueryRead | SchemaRead),
            (QueryRead, QueryRead | SchemaRead) => true,
            (SchemaRead, SchemaRead) => true,
            (HistoryRead, HistoryRead) => true,
            _ => false,
        }
    }
}

fn default_port() -> u16 {
    5432
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_implication_matches_spec() {
        assert!(Action::QueryWrite.includes(Action::QueryRead));
        assert!(Action::QueryWrite.includes(Action::SchemaRead));
        assert!(Action::QueryRead.includes(Action::SchemaRead));
        assert!(!Action::SchemaRead.includes(Action::QueryRead));
        assert!(!Action::QueryRead.includes(Action::QueryWrite));
        // History is its own track.
        assert!(Action::HistoryRead.includes(Action::HistoryRead));
        assert!(!Action::QueryWrite.includes(Action::HistoryRead));
        assert!(!Action::HistoryRead.includes(Action::SchemaRead));
    }

    #[test]
    fn server_defaults_apply() {
        let yaml = r#"
            name: dev
            kind: postgres
            host: localhost
        "#;
        let server: Server = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(server.port, 5432);
        assert_eq!(server.tls, Tls::Required);
        assert!(server.databases.is_empty());
    }
}
