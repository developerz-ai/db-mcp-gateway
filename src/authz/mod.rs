//! Authorization: group-grant evaluation for MCP tool calls.
//!
//! `can_see_server` (used by `list_servers`) gives a binary visible/hidden
//! answer. `evaluate(action, server, database)` is the canonical per-call
//! check — used by every action-gated tool from #4 onward. It returns either
//! `Decision::Allow { constraints }` (merged most-restrictively across every
//! matching grant) or `Decision::Deny`.
//!
//! `evaluate_effective` / `can_see_server_effective` (since #49) fold a
//! per-identity slice of DB-loaded grants into the same merge engine. The
//! YAML and DB sources are symmetric — neither source is privileged, the
//! most-restrictive constraint always wins on overlap.
//!
//! Security-required (see CLAUDE.md). The contract: a request is allowed iff
//! *some* grant matches. Absence of a matching grant denies — no implicit
//! upgrade from group membership alone (spec 06 §Evaluation). Most-restrictive
//! merging means being in two groups never *upgrades* your access.

pub mod cache;
pub mod effective;
#[cfg(test)]
mod effective_proptests;
#[cfg(test)]
mod evaluate_tests;
pub mod loader;
#[cfg(test)]
mod merge_proptests;
pub mod patch;
#[cfg(test)]
mod patch_proptests;
#[cfg(test)]
mod proptest_support;
#[cfg(test)]
mod resolver_proptests;
#[cfg(test)]
mod wildcard_proptests;

pub use cache::PermissionsCache;
pub use effective::{can_see_server_effective, evaluate_effective};
pub use loader::{LoadError, load_db_grants_for};
pub use patch::ConstraintsPatch;

use crate::auth::Identity;
use crate::config::{Action, Constraints, Grant, Permission, Server};

/// Outcome of an `evaluate` call. `Allow` carries the merged constraints the
/// executor must enforce (statement timeout, row limit, reason requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { constraints: Constraints },
    Deny,
}

/// Returns true iff `identity` has at least one grant that can actually apply
/// to `server` — i.e. the grant targets this server (or `*`) AND names a
/// database that exists on it (or `*`). Used to filter the `list_servers`
/// output so a user never learns of a server they have zero usable grants on.
///
/// A grant whose database doesn't exist on the matched server is treated as
/// non-applicable. Otherwise a stale grant on `database: app-typo` would still
/// reveal the server in `list_servers`, even though no real action against it
/// could ever succeed.
pub fn can_see_server(identity: &Identity, server: &Server, permissions: &[Permission]) -> bool {
    permissions
        .iter()
        .filter(|perm| identity.groups.iter().any(|g| g == &perm.group))
        .flat_map(|perm| perm.grants.iter())
        .any(|grant| grant_can_see(grant, server))
}

/// Per-call authz check. The action passed is what the *tool* needs; matching
/// grants are those whose action *includes* the requested one (see
/// `Action::includes` — `query_write` ⊇ `query_read` ⊇ `schema_read`).
pub fn evaluate(
    identity: &Identity,
    action: Action,
    server: &str,
    database: &str,
    permissions: &[Permission],
) -> Decision {
    evaluate_effective(identity, action, server, database, permissions, &[])
}

/// Helper: check if a grant allows viewing a server (used by both
/// can_see_server variants). Verifies server name matches and database
/// exists on that server.
pub fn grant_can_see(grant: &Grant, server: &Server) -> bool {
    let server_match = grant.server == "*" || grant.server == server.name;
    if !server_match {
        return false;
    }
    grant.database == "*" || server.databases.iter().any(|db| db.name == grant.database)
}

/// Helper: check if a grant applies to an action on a server/database pair.
/// Used by both evaluate variants.
pub fn grant_applies(grant: &Grant, action: Action, server: &str, database: &str) -> bool {
    (grant.server == "*" || grant.server == server)
        && (grant.database == "*" || grant.database == database)
        && grant.action.includes(action)
}

/// Merge two `Constraints` most-restrictively. Pure — same inputs, same
/// output — so property tests can hammer it freely.
///
/// Rule per spec 06: lowest `row_limit` wins, lowest `statement_timeout_ms`
/// wins, `require_reason: true` always wins. `None` on either side means
/// "no constraint from this side" — the other side's value carries through.
pub fn merge(a: &Constraints, b: &Constraints) -> Constraints {
    Constraints {
        require_reason: a.require_reason || b.require_reason,
        row_limit: min_option(a.row_limit, b.row_limit),
        statement_timeout_ms: min_option(a.statement_timeout_ms, b.statement_timeout_ms),
    }
}

fn min_option<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}
