//! The merge scope is the *requested* action (spec 06 §Evaluation, steps
//! 3–4): only grants whose action includes the requested one decide the call
//! and feed the most-restrictive merge. A grant outside that set is inert —
//! a `query_read` grant's caps never bind a `query_write` call — while a
//! `query_write` grant, which includes `query_read`, does bind a read.

use proptest::prelude::*;

use super::proptest_support::{
    TEST_GROUP, any_action, any_constraints, as_yaml_for, identity_in, no_more_permissive_than,
};
use super::{Decision, evaluate_effective, merge};
use crate::config::{Action, Constraints, Grant};

fn grant(action: Action, constraints: Constraints) -> Grant {
    Grant {
        server: "prod".into(),
        database: "app".into(),
        action,
        constraints,
    }
}

fn decide(yaml: &[Grant], db: &[Grant], action: Action) -> Decision {
    evaluate_effective(
        &identity_in(TEST_GROUP),
        action,
        "prod",
        "app",
        &as_yaml_for(TEST_GROUP, yaml.to_vec()),
        db,
    )
}

fn any_grants() -> impl Strategy<Value = Vec<Grant>> {
    proptest::collection::vec(
        (any_action(), any_constraints()).prop_map(|(a, c)| grant(a, c)),
        0..6,
    )
}

/// Grants of actions that do not include `QueryWrite`: everything but a
/// write grant.
fn any_non_write_grants() -> impl Strategy<Value = Vec<Grant>> {
    let action = prop_oneof![
        Just(Action::SchemaRead),
        Just(Action::QueryRead),
        Just(Action::HistoryRead),
    ];
    proptest::collection::vec(
        (action, any_constraints()).prop_map(|(a, c)| grant(a, c)),
        0..6,
    )
}

fn in_scope(grants: &[Grant], action: Action) -> Vec<Grant> {
    grants
        .iter()
        .filter(|g| g.action.includes(action))
        .cloned()
        .collect()
}

proptest! {
    /// Dropping every grant whose action does not include the requested one
    /// never changes the decision, in either source.
    #[test]
    fn grants_outside_the_requested_action_are_inert(
        yaml in any_grants(),
        db in any_grants(),
        action in any_action(),
    ) {
        prop_assert_eq!(
            decide(&yaml, &db, action),
            decide(&in_scope(&yaml, action), &in_scope(&db, action), action),
        );
    }

    /// A read (or schema, or history) grant's caps never leak into a write:
    /// the write decision is the merge of the write grants alone, whichever
    /// source the other grants sit in.
    #[test]
    fn read_caps_never_bind_a_write(
        write in proptest::collection::vec(any_constraints(), 1..4),
        others in any_non_write_grants(),
        others_in_db in any::<bool>(),
    ) {
        let expected = write.iter().fold(Constraints::default(), |acc, c| merge(&acc, c));
        let write_grants: Vec<Grant> =
            write.into_iter().map(|c| grant(Action::QueryWrite, c)).collect();
        let decision = if others_in_db {
            decide(&write_grants, &others, Action::QueryWrite)
        } else {
            let all: Vec<Grant> = write_grants.iter().chain(&others).cloned().collect();
            decide(&all, &[], Action::QueryWrite)
        };
        prop_assert_eq!(decision, Decision::Allow { constraints: expected });
    }

    /// Without a write grant no amount of read authority allows a write.
    #[test]
    fn read_grants_never_allow_a_write(others in any_non_write_grants()) {
        prop_assert_eq!(decide(&others, &[], Action::QueryWrite), Decision::Deny);
        prop_assert_eq!(decide(&[], &others, Action::QueryWrite), Decision::Deny);
    }

    /// The other direction is not symmetric: `query_write` includes
    /// `query_read` and `schema_read`, so a write grant is a matching grant
    /// for a read and its caps merge into it.
    #[test]
    fn write_caps_bind_a_read(read in any_constraints(), write in any_constraints()) {
        let grants = [grant(Action::QueryRead, read.clone()), grant(Action::QueryWrite, write.clone())];
        for asked in [Action::QueryRead, Action::SchemaRead] {
            prop_assert_eq!(
                decide(&grants, &[], asked),
                Decision::Allow { constraints: merge(&read, &write) },
            );
        }
    }

    /// Within one requested action, most restrictive wins: the merged
    /// constraints are no more permissive than any in-scope grant's.
    #[test]
    fn most_restrictive_wins_within_an_action(
        yaml in any_grants(),
        db in any_grants(),
        action in any_action(),
    ) {
        let scoped: Vec<Grant> = in_scope(&yaml, action)
            .into_iter()
            .chain(in_scope(&db, action))
            .collect();
        match decide(&yaml, &db, action) {
            Decision::Deny => prop_assert!(scoped.is_empty()),
            Decision::Allow { constraints } => {
                prop_assert!(!scoped.is_empty());
                for g in &scoped {
                    prop_assert!(no_more_permissive_than(&constraints, &g.constraints));
                }
            }
        }
    }
}
