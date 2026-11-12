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

mod target;

pub use target::{Database, Server, ServerKind, Tls};

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
    /// In-flight request cap for this identity, replacing the gateway-wide
    /// per-identity cap (`MAX_CONCURRENT_PER_IDENTITY`, default 16) so a fleet
    /// of agents behind one token is not throttled as one user. The global
    /// cap still applies. Absent → the per-identity default.
    #[serde(default)]
    pub max_concurrent_requests: Option<u32>,
    /// Reject calls that do not carry the upstream attribution headers
    /// (`x-dbmcp-run-id`, `x-dbmcp-on-behalf-of`). The headers are claimed by
    /// the caller, never verified, and never used for authz.
    #[serde(default)]
    pub require_upstream: bool,
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
}
