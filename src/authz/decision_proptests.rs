//! Decision-level safety properties of `evaluate_effective` (plan 101
//! slice 13 step 6): grant order is irrelevant, joining a group never
//! revokes, the read cap binds write grants too, and read grants never
//! authorize writes.

use proptest::prelude::*;

use super::proptest_support::{
    TEST_GROUP, any_action, any_grant, any_grants, any_request, as_yaml_for, identity_in,
    no_more_permissive_than,
};
use super::{Decision, evaluate_effective, grant_applies};
use crate::config::{Action, Grant, Permission};

const OTHER_GROUP: &str = "h";

/// A grant list and a shuffled copy of it.
fn grants_and_permutation() -> impl Strategy<Value = (Vec<Grant>, Vec<Grant>)> {
    any_grants().prop_flat_map(|grants| (Just(grants.clone()), Just(grants).prop_shuffle()))
}

/// Grants whose action can never include `QueryWrite`.
fn any_non_write_grants() -> impl Strategy<Value = Vec<Grant>> {
    let non_write = prop_oneof![
        Just(Action::SchemaRead),
        Just(Action::QueryRead),
        Just(Action::HistoryRead),
    ];
    proptest::collection::vec((any_grant(), non_write), 0..6).prop_map(|pairs| {
        pairs
            .into_iter()
            .map(|(grant, action)| Grant { action, ..grant })
            .collect()
    })
}

proptest! {
    /// Grant order in YAML or in the DB slice never changes the decision.
    #[test]
    fn decision_is_invariant_under_grant_order(
        (yaml, yaml_shuffled) in grants_and_permutation(),
        (db, db_shuffled) in grants_and_permutation(),
        (s, d, a) in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let original = evaluate_effective(&id, a, &s, &d, &as_yaml_for(TEST_GROUP, yaml), &db);
        let permuted = evaluate_effective(
            &id, a, &s, &d, &as_yaml_for(TEST_GROUP, yaml_shuffled), &db_shuffled,
        );
        prop_assert_eq!(original, permuted);
    }

    /// Joining a second group never turns Allow into Deny, and never
    /// loosens the constraints the first group's grants imposed.
    #[test]
    fn adding_a_group_never_revokes_or_loosens(
        mine in any_grants(),
        theirs in any_grants(),
        (s, d, a) in any_request(),
    ) {
        let permissions: Vec<Permission> = as_yaml_for(TEST_GROUP, mine)
            .into_iter()
            .chain(as_yaml_for(OTHER_GROUP, theirs))
            .collect();
        let before = evaluate_effective(&identity_in(TEST_GROUP), a, &s, &d, &permissions, &[]);
        let mut joined = identity_in(TEST_GROUP);
        joined.groups.push(OTHER_GROUP.to_string());
        let after = evaluate_effective(&joined, a, &s, &d, &permissions, &[]);

        if let Decision::Allow { constraints: was } = &before {
            let Decision::Allow { constraints: now } = &after else {
                return Err(TestCaseError::fail("joining a group revoked an allow"));
            };
            prop_assert!(no_more_permissive_than(now, was), "{now:?} looser than {was:?}");
        }
    }

    /// The merged constraints never exceed any single grant that applied.
    #[test]
    fn allow_is_bounded_by_every_applying_grant(
        yaml in any_grants(),
        db in any_grants(),
        (s, d, a) in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let decision = evaluate_effective(&id, a, &s, &d, &as_yaml_for(TEST_GROUP, yaml.clone()), &db);
        if let Decision::Allow { constraints } = decision {
            for grant in yaml.iter().chain(&db).filter(|g| grant_applies(g, a, &s, &d)) {
                prop_assert!(
                    no_more_permissive_than(&constraints, &grant.constraints),
                    "{constraints:?} looser than applying {grant:?}"
                );
            }
        }
    }

    /// `run_query` enforces the `QueryRead` decision's constraints even for a
    /// writer. Every grant that satisfies `QueryWrite` also satisfies
    /// `QueryRead`, so the read decision is never looser than the write
    /// one: a `query_write` grant cannot dodge a tighter `query_read` cap.
    #[test]
    fn read_constraints_are_never_looser_than_write_constraints(
        yaml in any_grants(),
        db in any_grants(),
        (s, d, _) in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let perms = as_yaml_for(TEST_GROUP, yaml);
        let read = evaluate_effective(&id, Action::QueryRead, &s, &d, &perms, &db);
        let write = evaluate_effective(&id, Action::QueryWrite, &s, &d, &perms, &db);
        if let Decision::Allow { constraints: write } = &write {
            let Decision::Allow { constraints: read } = &read else {
                return Err(TestCaseError::fail("write allowed but read denied"));
            };
            prop_assert!(no_more_permissive_than(read, write), "{read:?} looser than {write:?}");
        }
    }

    /// No combination of read-only grants, from either source, authorizes a
    /// write.
    #[test]
    fn read_grants_never_satisfy_query_write(
        yaml in any_non_write_grants(),
        db in any_non_write_grants(),
        (s, d, _) in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let decision = evaluate_effective(
            &id, Action::QueryWrite, &s, &d, &as_yaml_for(TEST_GROUP, yaml), &db,
        );
        prop_assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn only_query_write_includes_query_write(action in any_action()) {
        prop_assert_eq!(action.includes(Action::QueryWrite), action == Action::QueryWrite);
    }
}
