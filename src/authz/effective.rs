//! DB-grant aware evaluation with symmetric YAML/DB merging (#49).
//!
//! `can_see_server_effective` and `evaluate_effective` extend the YAML-only
//! versions with a per-identity DB-grant slice. Both sources merge
//! most-restrictively — neither is privileged. [`matching_grants`] is the one
//! place a grant is judged to apply; evaluation, discovery and the admin
//! `explain` route all read it, so they cannot drift.
//!
//! Resolver-level safety proofs live in `effective_proptests` (#50, test-only module).

use chrono::{DateTime, Utc};

use crate::auth::Identity;
use crate::config::schema::Subject;
use crate::config::{Action, Constraints, Grant, Permission, Server};

use super::{Decision, grant_applies, merge, subject_matches};

/// `can_see_server` extended with a per-identity DB-grant slice (#49).
/// Symmetric merge: a server is visible if YAML *or* DB grants make it so.
/// An expired DB grant reveals nothing.
pub fn can_see_server_effective(
    identity: &Identity,
    server: &Server,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> bool {
    let now = Utc::now();
    super::can_see_server(identity, server, yaml_permissions)
        || db_grants_for_identity
            .iter()
            .any(|grant| grant.is_live_at(now) && super::grant_can_see(grant, server))
}

/// Where a matched grant came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantSource<'a> {
    /// A `permissions:` block, by its subject.
    Yaml(&'a Subject),
    /// Index into the DB-grant slice the caller passed.
    Db(usize),
}

/// One grant that applies to a request.
#[derive(Debug, Clone, Copy)]
pub struct MatchedGrant<'a> {
    pub source: GrantSource<'a>,
    pub grant: &'a Grant,
}

/// Every grant that applies to `(action, server, database)` for `identity`
/// at `now`: YAML blocks whose subject matches the identity, then the DB
/// grants (pre-resolved to this identity by the loader, so they skip the
/// subject filter). Expired grants never match.
pub fn matching_grants<'a>(
    identity: &'a Identity,
    action: Action,
    target: (&'a str, &'a str),
    yaml_permissions: &'a [Permission],
    db_grants_for_identity: &'a [Grant],
    now: DateTime<Utc>,
) -> impl Iterator<Item = MatchedGrant<'a>> + 'a {
    let (server, database) = target;
    let applies = move |g: &Grant| g.is_live_at(now) && grant_applies(g, action, server, database);
    let yaml = yaml_permissions
        .iter()
        .filter(|p| subject_matches(&p.subject, identity))
        .flat_map(|p| {
            p.grants.iter().map(|grant| MatchedGrant {
                source: GrantSource::Yaml(&p.subject),
                grant,
            })
        });
    let db = db_grants_for_identity
        .iter()
        .enumerate()
        .map(|(index, grant)| MatchedGrant {
            source: GrantSource::Db(index),
            grant,
        });
    yaml.chain(db).filter(move |m| applies(m.grant))
}

/// Fold matched grants into a decision: allowed iff at least one matched,
/// constraints merged most-restrictively.
pub fn decide<'a>(matches: impl IntoIterator<Item = MatchedGrant<'a>>) -> Decision {
    let mut merged: Option<Constraints> = None;
    for m in matches {
        let c = &m.grant.constraints;
        merged = Some(match merged {
            Some(acc) => merge(&acc, c),
            None => merge(&Constraints::default(), c),
        });
    }
    match merged {
        Some(constraints) => Decision::Allow { constraints },
        None => Decision::Deny,
    }
}

/// `evaluate` extended with a per-identity DB-grant slice (#49). Both sets
/// feed the same most-restrictive merge — there is no priority between them.
pub fn evaluate_effective(
    identity: &Identity,
    action: Action,
    server: &str,
    database: &str,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> Decision {
    evaluate_effective_at(
        identity,
        action,
        (server, database),
        yaml_permissions,
        db_grants_for_identity,
        Utc::now(),
    )
}

/// [`evaluate_effective`] at a fixed instant — what expiry tests pin.
pub fn evaluate_effective_at(
    identity: &Identity,
    action: Action,
    target: (&str, &str),
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
    now: DateTime<Utc>,
) -> Decision {
    decide(matching_grants(
        identity,
        action,
        target,
        yaml_permissions,
        db_grants_for_identity,
        now,
    ))
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
    let now = Utc::now();
    ALL_ACTIONS
        .into_iter()
        .filter_map(|action| {
            match evaluate_effective_at(
                identity,
                action,
                (server, database),
                yaml_permissions,
                db_grants_for_identity,
                now,
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
