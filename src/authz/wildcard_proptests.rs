//! Property tests for `database = "*"` wildcard grants (#55).
//!
//! Codifies the three wildcard properties spec 12 §"Wildcard" calls out
//! (`docs/initial-idea/12-dynamic-permissions.md` lines 189–191):
//!
//!  1. *Wildcards do not widen permissions on a database the user has a
//!     more-specific grant on — the per-database grant's constraints intersect
//!     with the wildcard's, most-restrictive wins.*
//!  2. *Wildcards still go through the same constraint engine — a wildcard
//!     `row_limit: 100` does not become unlimited just because it matches
//!     every db.*
//!  3. *Absence is the deny — wildcards do not change this.*
//!
//! The wildcard match itself lives in [`super::grant_applies`] at
//! `(grant.database == "*" || grant.database == database)`. These tests pin
//! the *behavior*, not the implementation: a future rewrite that keeps the
//! contract passes; one that quietly relaxes a constraint or widens absence
//! into allow fails.
//!
//! ## Note on "explicit deny beats wildcard"
//!
//! Issue #55's body lists "Explicit deny beats wildcard, always" as a
//! property to test. The model has no explicit-deny token — spec 12 line 189
//! states this explicitly: *"We don't have explicit denies today; absence is
//! the deny."* The closest meaningful invariant is
//! [`absence_is_silent_even_with_wildcards`]: a user whose groups don't
//! match cannot be allowed by a wildcard that exists for another group.

use super::{Decision, evaluate_effective};
use crate::auth::{Identity, SessionId};
use crate::config::{Action, Constraints, Grant, Permission};
use proptest::prelude::*;

const TEST_GROUP: &str = "g";

/// Small alphabet — see the matching helper in [`super::effective_proptests`]
/// for the rationale. The point of a tiny universe is forcing proptest into
/// the overlap cases, not chasing string uniqueness.
fn any_concrete_server() -> impl Strategy<Value = String> {
    prop_oneof![Just("prod".to_string()), Just("staging".to_string())]
}

fn any_concrete_db() -> impl Strategy<Value = String> {
    prop_oneof![Just("app".to_string()), Just("billing".to_string())]
}

fn any_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::SchemaRead),
        Just(Action::QueryRead),
        Just(Action::QueryWrite),
        Just(Action::HistoryRead),
    ]
}

fn any_constraints() -> impl Strategy<Value = Constraints> {
    (
        any::<bool>(),
        proptest::option::of(0u32..=1_000_000),
        proptest::option::of(0u32..=600_000),
    )
        .prop_map(
            |(require_reason, row_limit, statement_timeout_ms)| Constraints {
                require_reason,
                row_limit,
                statement_timeout_ms,
            },
        )
}

fn identity_in(group: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: "test-sub".to_string(),
        user_email: "test@example.com".to_string(),
        groups: vec![group.to_string()],
    }
}

/// Wrap a flat `Vec<Grant>` into a `Permission` keyed on `group`.
fn as_yaml_for(group: &str, grants: Vec<Grant>) -> Vec<Permission> {
    vec![Permission {
        group: group.to_string(),
        grants,
    }]
}

/// Field-wise "no more permissive than" predicate. Lifted from
/// [`super::effective_proptests`]; the wildcard properties depend on the
/// same ordering on `Constraints`.
fn no_more_permissive_than(a: &Constraints, b: &Constraints) -> bool {
    let reason_ok = a.require_reason || !b.require_reason;
    let rl_ok = match (a.row_limit, b.row_limit) {
        (Some(av), Some(bv)) => av <= bv,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => true,
    };
    let to_ok = match (a.statement_timeout_ms, b.statement_timeout_ms) {
        (Some(av), Some(bv)) => av <= bv,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => true,
    };
    reason_ok && rl_ok && to_ok
}

proptest! {
    /// **Wildcard db matches every database.** A grant with `database = "*"`
    /// on server `S` allows the action on `(S, ANY_DB)`. The point: no db
    /// name on the request side can escape the wildcard's reach.
    #[test]
    fn wildcard_db_matches_every_database(
        server in any_concrete_server(),
        db in any_concrete_db(),
        action in any_action(),
        constraints in any_constraints(),
    ) {
        let id = identity_in(TEST_GROUP);
        let wildcard = Grant {
            server: server.clone(),
            database: "*".to_string(),
            action,
            constraints,
        };
        let decision = evaluate_effective(
            &id, action, &server, &db,
            &as_yaml_for(TEST_GROUP, vec![wildcard]),
            &[],
        );
        prop_assert!(
            matches!(decision, Decision::Allow { .. }),
            "wildcard db grant must allow any database; got {decision:?}"
        );
    }

    /// **Wildcard never widens a specific grant.** A wildcard grant merged
    /// with a more-specific grant on the same `(server, db, action)` must
    /// produce constraints no more permissive than the specific grant's.
    /// Spec 12 line 190.
    #[test]
    fn wildcard_never_widens_a_specific_grant(
        server in any_concrete_server(),
        db in any_concrete_db(),
        action in any_action(),
        wc_constraints in any_constraints(),
        sp_constraints in any_constraints(),
    ) {
        let id = identity_in(TEST_GROUP);
        let wildcard = Grant {
            server: server.clone(),
            database: "*".to_string(),
            action,
            constraints: wc_constraints,
        };
        let specific = Grant {
            server: server.clone(),
            database: db.clone(),
            action,
            constraints: sp_constraints.clone(),
        };
        let decision = evaluate_effective(
            &id, action, &server, &db,
            &as_yaml_for(TEST_GROUP, vec![wildcard, specific]),
            &[],
        );
        match decision {
            Decision::Allow { constraints: merged } => {
                prop_assert!(
                    no_more_permissive_than(&merged, &sp_constraints),
                    "merged {merged:?} must not be laxer than the specific grant {sp_constraints:?}"
                );
            }
            Decision::Deny => prop_assert!(false, "two applicable grants must allow"),
        }
    }

    /// **Wildcard constraints preserved.** A wildcard grant alone must
    /// produce constraints equal to its own — the cap doesn't dissolve just
    /// because the grant covers many DBs. Spec 12 line 191.
    #[test]
    fn wildcard_constraints_preserved_across_dbs(
        server in any_concrete_server(),
        db_a in any_concrete_db(),
        db_b in any_concrete_db(),
        action in any_action(),
        constraints in any_constraints(),
    ) {
        let id = identity_in(TEST_GROUP);
        let wildcard = Grant {
            server: server.clone(),
            database: "*".to_string(),
            action,
            constraints: constraints.clone(),
        };
        let perms = as_yaml_for(TEST_GROUP, vec![wildcard]);
        let dec_a = evaluate_effective(&id, action, &server, &db_a, &perms, &[]);
        let dec_b = evaluate_effective(&id, action, &server, &db_b, &perms, &[]);
        // Same wildcard grant, two different DBs — both decisions must be
        // identical Allows whose constraints field-equal the grant's.
        prop_assert_eq!(&dec_a, &dec_b);
        if let Decision::Allow { constraints: c } = dec_a {
            prop_assert_eq!(c, constraints);
        } else {
            prop_assert!(false, "wildcard must allow");
        }
    }

    /// **Wildcards respect the action hierarchy.** Wildcard expands the
    /// *target*, not the action. A wildcard `schema_read` grant cannot
    /// satisfy a `query_read` request; a `query_read` grant cannot satisfy
    /// `query_write`.
    #[test]
    fn wildcard_respects_action_hierarchy(
        server in any_concrete_server(),
        db in any_concrete_db(),
        grant_action in any_action(),
        request_action in any_action(),
        constraints in any_constraints(),
    ) {
        // Only test cases where the grant action does NOT include the
        // request action — the property is about denials in that regime.
        prop_assume!(!grant_action.includes(request_action));

        let id = identity_in(TEST_GROUP);
        let wildcard = Grant {
            server: server.clone(),
            database: "*".to_string(),
            action: grant_action,
            constraints,
        };
        let decision = evaluate_effective(
            &id, request_action, &server, &db,
            &as_yaml_for(TEST_GROUP, vec![wildcard]),
            &[],
        );
        prop_assert_eq!(
            decision,
            Decision::Deny,
            "wildcard grant of {:?} must not satisfy {:?} request",
            grant_action,
            request_action
        );
    }

    /// **Double wildcard matches anything.** `server="*"` + `database="*"`
    /// (the "superuser" wildcard from spec 12) allows the action on every
    /// `(server, db)` pair — but still only for actions the grant covers.
    #[test]
    fn double_wildcard_matches_any_server_db(
        server in any_concrete_server(),
        db in any_concrete_db(),
        action in any_action(),
        constraints in any_constraints(),
    ) {
        let id = identity_in(TEST_GROUP);
        let wildcard = Grant {
            server: "*".to_string(),
            database: "*".to_string(),
            action,
            constraints,
        };
        let decision = evaluate_effective(
            &id, action, &server, &db,
            &as_yaml_for(TEST_GROUP, vec![wildcard]),
            &[],
        );
        prop_assert!(
            matches!(decision, Decision::Allow { .. }),
            "double wildcard must allow ({server}, {db}); got {decision:?}"
        );
    }

    /// **Absence is silent — even under wildcards.** A wildcard grant in
    /// some group `G` cannot allow a user who isn't in `G`. Spec 06
    /// §Evaluation: absence is the deny; spec 12 line 189: wildcards don't
    /// change this. The closest meaningful interpretation of #55's "explicit
    /// deny beats wildcard" bullet.
    #[test]
    fn absence_is_silent_even_with_wildcards(
        server in any_concrete_server(),
        db in any_concrete_db(),
        action in any_action(),
        constraints in any_constraints(),
    ) {
        // User is in "outsider"; the wildcard lives in "insider".
        let id = identity_in("outsider");
        let wildcard = Grant {
            server: "*".to_string(),
            database: "*".to_string(),
            action,
            constraints,
        };
        let decision = evaluate_effective(
            &id, action, &server, &db,
            &as_yaml_for("insider", vec![wildcard]),
            &[],
        );
        prop_assert_eq!(
            decision,
            Decision::Deny,
            "wildcard in group not held by the user must not allow"
        );
    }
}
