//! DB-grant aware evaluation with symmetric YAML/DB merging (#49).
//!
//! `can_see_server_effective` and `evaluate_effective` extend the YAML-only
//! versions with a per-identity DB-grant slice. Both sources merge
//! most-restrictively — neither is privileged. This module encapsulates
//! that logic and its tests.
//!
//! Resolver-level safety proofs live in `effective_proptests` (#50, test-only module).

use crate::auth::Identity;
use crate::config::{Action, Constraints, Grant, Permission, Server};

use super::{Decision, grant_applies, merge};

/// `can_see_server` extended with a per-identity DB-grant slice (#49).
/// Symmetric merge: a server is visible if YAML *or* DB grants make it so.
pub fn can_see_server_effective(
    identity: &Identity,
    server: &Server,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> bool {
    super::can_see_server(identity, server, yaml_permissions)
        || db_grants_for_identity
            .iter()
            .any(|grant| super::grant_can_see(grant, server))
}

/// `evaluate` extended with a per-identity DB-grant slice (#49).
///
/// YAML grants are group-keyed; DB grants are user-keyed and pre-resolved to
/// this `identity` by the loader, so they bypass the group filter. Both sets
/// feed the same most-restrictive merge — there is no priority between them.
pub fn evaluate_effective(
    identity: &Identity,
    action: Action,
    server: &str,
    database: &str,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> Decision {
    let yaml_matches = yaml_permissions
        .iter()
        .filter(|p| identity.groups.iter().any(|g| g == &p.group))
        .flat_map(|p| p.grants.iter())
        .filter(|g| grant_applies(g, action, server, database));

    let db_matches = db_grants_for_identity
        .iter()
        .filter(|g| grant_applies(g, action, server, database));

    let mut merged_some = false;
    let mut merged = Constraints::default();
    for c in yaml_matches.chain(db_matches).map(|g| &g.constraints) {
        merged = merge(&merged, c);
        merged_some = true;
    }
    if merged_some {
        Decision::Allow {
            constraints: merged,
        }
    } else {
        Decision::Deny
    }
}

/// Every action a grant can name, in hierarchy order — the questions
/// [`held_actions`] asks [`evaluate_effective`].
pub const ALL_ACTIONS: [Action; 4] = [
    Action::SchemaRead,
    Action::QueryRead,
    Action::QueryWrite,
    Action::HistoryRead,
];

/// One action `identity` holds on a `(server, database)`, with the merged
/// constraints evaluation enforces for exactly that action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAction {
    pub action: Action,
    pub constraints: Constraints,
}

/// What [`evaluate_effective`] answers for each of [`ALL_ACTIONS`] on
/// `(server, database)`: the allowed ones, in that order. Empty means no
/// access. The discovery tools report this, so what they show is what a
/// call is held to — there is no second evaluation path to drift.
pub fn held_actions(
    identity: &Identity,
    server: &str,
    database: &str,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> Vec<HeldAction> {
    ALL_ACTIONS
        .into_iter()
        .filter_map(|action| {
            match evaluate_effective(
                identity,
                action,
                server,
                database,
                yaml_permissions,
                db_grants_for_identity,
            ) {
                Decision::Allow { constraints } => Some(HeldAction {
                    action,
                    constraints,
                }),
                Decision::Deny => None,
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "effective_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "held_actions_proptests.rs"]
mod held_actions_proptests;
