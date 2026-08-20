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
            ServerKind::Postgres | ServerKind::Mongo => true,
            ServerKind::Mysql | ServerKind::Mssql => false,
        }
    }
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
    /// Optional authentication database for backends where the role lives
    /// somewhere other than the target database (mongo's `authSource`).
    /// `None` falls back to `name` — the least-privilege per-db user
    /// pattern. Operators set this to `"admin"` when bootstrapping with
    /// the container's root user. Ignored by pg (which authenticates
    /// against the connected database).
    #[serde(default)]
    pub auth_database: Option<String>,
}

/// A headless (non-interactive) caller: a named service identity carrying a
/// static bearer token, one permissions group, and nothing else. Design:
/// website/docs/initial-idea/14-service-tokens.md.
///
/// The token is a secret reference — never an inline literal in production —
/// resolved once at boot into `auth::ServiceTokenStore`. There is no in-band
/// mint/revoke API: issuance and revocation are GitOps edits to this list
/// plus a secret-store update, so every change is reviewed by PR.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAccount {
    /// Stable service identity (`ci-bot`). Becomes the audit identity
    /// `service:<name>`; charset/length rules are enforced at boot so audit
    /// fields stay clean and unambiguous.
    pub name: String,
    /// The single permissions group this token acts as. Must be declared in
    /// `permissions:` (an empty-grants block is the way to recognize a group
    /// that grants nothing) and must never be the admin group — both checked
    /// at boot, which is what keeps service tokens off the `/admin/*` surface
    /// without touching the admin middleware.
    pub group: String,
    /// `${ENV:…}` / `${FILE:…}` reference (inline literal tolerated for
    /// dev/test, same rule as `Database.password`).
    pub token: Password,
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
/// See `Action::includes` and website/docs/initial-idea/06-permissions.md.
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

/// `logging:` block (spec 07 §Storage). Only `stream` exists today —
/// `hot_retention_days` stays env-driven (`AUDIT_RETENTION_DAYS`) until #16
/// folds retention into YAML, and `archive` isn't implemented yet (#218
/// tracks it). Absent `logging:` in YAML is identical to an empty one: no
/// stream sinks, which is the pre-#218 behavior.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingBlock {
    #[serde(default)]
    pub stream: Vec<StreamSinkConfig>,
}

/// One configured stream sink (spec 07 §Storage "Stream" tier). Fire-and-
/// forget export of every audit row, independent of and additional to the
/// mandatory hot-tier Postgres write — a sink outage must never fail an
/// agent's request. `stdout` and `syslog` are shipped; `otlp` is tracked in
/// #218.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum StreamSinkConfig {
    /// Emit the full audit row as a structured `tracing` event (target
    /// `audit_stream`) so it rides the gateway's existing JSON-per-line
    /// stdout log — no new transport, just a distinct, filterable target
    /// operators can route to Splunk/Datadog alongside application logs.
    Stdout,
    /// Send an RFC 5424 message over UDP to a syslog receiver. `host`/`port`
    /// mirror `Server`'s shape rather than a combined `"host:port"` string —
    /// consistent with the rest of this schema, and it sidesteps parsing a
    /// address format at deserialize time.
    Syslog { host: String, port: u16 },
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

    /// The dispatchable set must match `exec::AdapterRegistry::get_or_open`.
    /// Pin it here so flipping a kind's support is a deliberate, reviewed edit.
    #[test]
    fn has_adapter_matches_wired_dispatch() {
        assert!(ServerKind::Postgres.has_adapter());
        assert!(ServerKind::Mongo.has_adapter());
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
}
