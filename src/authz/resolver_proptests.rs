//! Resolver properties not covered by `effective_proptests`: the decision is
//! a function of the grant *set* (order never matters), a zero bound is the
//! tightest bound (never "unset"), and `history_read` is disjoint from the
//! `query_write ⊇ query_read ⊇ schema_read` chain.

use proptest::prelude::*;

use super::proptest_support::{TEST_GROUP, any_action, any_constraints, as_yaml_for, identity_in};
use super::{Decision, evaluate_effective};
use crate::config::{Action, Constraints, Grant};

fn grant(action: Action, constraints: Constraints) -> Grant {
    Grant {
        server: "prod".into(),
        database: "app".into(),
        action,
        constraints,
    }
}

fn decide(yaml: Vec<Grant>, db: &[Grant], action: Action) -> Decision {
    let id = identity_in(TEST_GROUP);
    evaluate_effective(
        &id,
        action,
        "prod",
        "app",
        &as_yaml_for(TEST_GROUP, yaml),
        db,
    )
}

fn any_grants() -> impl Strategy<Value = Vec<Grant>> {
    proptest::collection::vec(
        (any_action(), any_constraints()).prop_map(|(a, c)| grant(a, c)),
        0..6,
    )
}

proptest! {
    /// Reordering grants within either source never changes the decision.
    #[test]
    fn decision_is_grant_order_independent(
        yaml in any_grants(),
        db in any_grants(),
        action in any_action(),
    ) {
        let forward = decide(yaml.clone(), &db, action);
        let mut yaml_rev = yaml;
        yaml_rev.reverse();
        let mut db_rev = db;
        db_rev.reverse();
        prop_assert_eq!(forward, decide(yaml_rev, &db_rev, action));
    }

    /// `row_limit: 0` / `statement_timeout_ms: 0` survive any merge: zero is
    /// the most restrictive bound, so a second grant can never lift it.
    #[test]
    fn zero_bound_is_never_relaxed(other in any_constraints(), zero_rows in any::<bool>()) {
        let zero = Constraints {
            require_reason: false,
            row_limit: zero_rows.then_some(0),
            statement_timeout_ms: (!zero_rows).then_some(0),
        };
        let grants = vec![grant(Action::QueryRead, zero), grant(Action::QueryRead, other)];
        let Decision::Allow { constraints } = decide(grants, &[], Action::QueryRead) else {
            return Err(TestCaseError::fail("two matching grants must allow"));
        };
        if zero_rows {
            prop_assert_eq!(constraints.row_limit, Some(0));
        } else {
            prop_assert_eq!(constraints.statement_timeout_ms, Some(0));
        }
    }

    /// `history_read` neither grants nor is granted by any query action, in
    /// either source.
    #[test]
    fn history_read_is_disjoint(c in any_constraints(), in_db in any::<bool>()) {
        let check = |held: Action, asked: Action| {
            let g = vec![grant(held, c.clone())];
            if in_db { decide(Vec::new(), &g, asked) } else { decide(g, &[], asked) }
        };
        for query in [Action::SchemaRead, Action::QueryRead, Action::QueryWrite] {
            prop_assert_eq!(check(Action::HistoryRead, query), Decision::Deny);
            prop_assert_eq!(check(query, Action::HistoryRead), Decision::Deny);
        }
    }
}
