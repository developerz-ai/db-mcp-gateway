//! Property tests for the symmetric YAML ⊕ DB resolver (#50).
//!
//! `evaluate_effective` (shipped in #49) merges YAML and DB grants through the
//! existing constraint-merge engine, with no priority between sources. The
//! `merge` proptests in [`super::proptests`] already prove the merge primitive
//! itself is associative, commutative, and monotonically narrowing. What
//! these tests prove is the **resolver-level** safety contract: no
//! permutation of `(yaml_grants, db_grants)` can let a user upgrade their
//! access beyond what either source alone would allow.
//!
//! ## Note on "explicit deny beats allow"
//!
//! Issue #50's scope mentions "explicit deny in either source beats any allow
//! in the other." This property does NOT apply in our model. Spec 12
//! §"Why merge symmetrically" explicitly rejects deny-overrides: an attacker
//! who compromises the admin API can only *narrow* access (DoS) or add new
//! grants — they cannot use absence-of-grant to revoke YAML's grants. The
//! "absence is the deny" semantic from spec 06 §Evaluation means there is no
//! `deny` token to encode. The closest meaningful property is
//! [`appending_non_matching_grant_is_a_noop`]: appending a grant that doesn't apply to `(s, d, a)`
//! cannot change the outcome. That's tested here.

use super::proptest_support::{
    TEST_GROUP, any_action, any_constraints, as_yaml_for, identity_in, no_more_permissive_than,
};
use super::{Decision, evaluate_effective, grant_applies};
use crate::config::{Action, Grant};
use proptest::prelude::*;

/// Small alphabet — the resolver doesn't care about the string values
/// themselves, only that wildcards (`*`) match anything and non-wildcards
/// must match exactly. Keeping the alphabet tiny lets proptest actually
/// explore the (yaml ∩ db) overlap case rather than getting lost in unique
/// random strings.
fn any_server() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("prod".to_string()),
        Just("staging".to_string()),
        Just("*".to_string()),
    ]
}

fn any_database() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("app".to_string()),
        Just("billing".to_string()),
        Just("*".to_string()),
    ]
}

fn any_grant() -> impl Strategy<Value = Grant> {
    (
        any_server(),
        any_database(),
        any_action(),
        any_constraints(),
    )
        .prop_map(|(server, database, action, constraints)| Grant {
            server,
            database,
            action,
            constraints,
        })
}

fn any_grants() -> impl Strategy<Value = Vec<Grant>> {
    proptest::collection::vec(any_grant(), 0..6)
}

/// Concrete `(server, database, action)` request — uses the non-wildcard
/// alphabet, since wildcards on the *request* side never appear in real
/// dispatch.
fn any_request() -> impl Strategy<Value = (String, String, Action)> {
    let req_server = prop_oneof![Just("prod".to_string()), Just("staging".to_string())];
    let req_db = prop_oneof![Just("app".to_string()), Just("billing".to_string())];
    (req_server, req_db, any_action())
}

proptest! {
    /// **Symmetric swap.** Swapping which set is "yaml" vs "db" must not
    /// change the resolver's decision. Codifies spec 12 §"Two sources, one
    /// engine" — there is no priority between sources.
    #[test]
    fn evaluate_is_symmetric_in_yaml_and_db(
        yaml in any_grants(),
        db in any_grants(),
        req in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let (s, d, a) = req;
        let with_yaml_first = evaluate_effective(&id, a, &s, &d, &as_yaml_for(TEST_GROUP, yaml.clone()), &db);
        let with_db_first = evaluate_effective(&id, a, &s, &d, &as_yaml_for(TEST_GROUP, db.clone()), &yaml);
        prop_assert_eq!(with_yaml_first, with_db_first);
    }

    /// **Monotone narrowing.** When the union allows, its constraints must be
    /// at most as permissive as the YAML-only constraints AND at most as
    /// permissive as the DB-only constraints. Belonging to more sources can
    /// only ever tighten the binding — never relax it.
    #[test]
    fn union_constraints_narrow_each_source(
        yaml in any_grants(),
        db in any_grants(),
        req in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let (s, d, a) = req;
        let yaml_perms = as_yaml_for(TEST_GROUP, yaml);
        let union = evaluate_effective(&id, a, &s, &d, &yaml_perms, &db);
        let yaml_only = evaluate_effective(&id, a, &s, &d, &yaml_perms, &[]);
        let db_only = evaluate_effective(&id, a, &s, &d, &[], &db);

        if let Decision::Allow { constraints: u } = &union {
            if let Decision::Allow { constraints: yo } = &yaml_only {
                prop_assert!(
                    no_more_permissive_than(u, yo),
                    "union {u:?} must not be laxer than yaml-only {yo:?}"
                );
            }
            if let Decision::Allow { constraints: dbo } = &db_only {
                prop_assert!(
                    no_more_permissive_than(u, dbo),
                    "union {u:?} must not be laxer than db-only {dbo:?}"
                );
            }
        }
    }

    /// **Allow union.** If either source alone allows the request, the union
    /// must allow it too. Guards against a regression where mixing the sources
    /// could turn an allow into a deny — a silent revocation of either YAML's
    /// or DB's intent. Reverse implication of `union_constraints_narrow_*`.
    #[test]
    fn union_allows_when_either_source_allows(
        yaml in any_grants(),
        db in any_grants(),
        req in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let (s, d, a) = req;
        let yaml_perms = as_yaml_for(TEST_GROUP, yaml);
        let yaml_only = evaluate_effective(&id, a, &s, &d, &yaml_perms, &[]);
        let db_only = evaluate_effective(&id, a, &s, &d, &[], &db);
        let union = evaluate_effective(&id, a, &s, &d, &yaml_perms, &db);

        let either_allows = matches!(yaml_only, Decision::Allow { .. })
            || matches!(db_only, Decision::Allow { .. });
        if either_allows {
            prop_assert!(
                matches!(union, Decision::Allow { .. }),
                "union must allow when either source allows; got {union:?}"
            );
        }
    }

    /// **Empty deny.** If neither source has any matching grant for the
    /// request, the resolver must deny. Spec 06 §Evaluation: absence is the
    /// deny — no implicit allow from group membership alone.
    #[test]
    fn empty_match_denies(req in any_request()) {
        let id = identity_in(TEST_GROUP);
        let (s, d, a) = req;
        prop_assert_eq!(
            evaluate_effective(&id, a, &s, &d, &[], &[]),
            Decision::Deny
        );
    }

    /// **Absence is silent.** Adding a grant that doesn't apply to `(s, d, a)`
    /// must leave the decision unchanged. This is the meaningful interpretation
    /// of the issue's "explicit deny" bullet: an absent-grant cannot operate
    /// as a deny-override against the other source. Pair with
    /// [`union_allows_when_either_source_allows`] — together they encode
    /// "absence has no negative semantics anywhere."
    #[test]
    fn appending_non_matching_grant_is_a_noop(
        base_yaml in any_grants(),
        base_db in any_grants(),
        extra in any_grant(),
        req in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let (s, d, a) = req;
        let yaml_perms = as_yaml_for(TEST_GROUP, base_yaml.clone());
        let before = evaluate_effective(&id, a, &s, &d, &yaml_perms, &base_db);

        // Skip the case where the extra grant *does* apply — that's the
        // narrowing property's domain, not this one.
        let extra_applies = grant_applies(&extra, a, &s, &d);
        prop_assume!(!extra_applies);

        // Append to YAML side: outcome must be unchanged.
        let mut yaml_extended = base_yaml.clone();
        yaml_extended.push(extra.clone());
        let after_yaml = evaluate_effective(
            &id,
            a,
            &s,
            &d,
            &as_yaml_for(TEST_GROUP, yaml_extended),
            &base_db,
        );
        prop_assert_eq!(&before, &after_yaml, "appending non-matching YAML grant changed outcome");

        // Append to DB side: outcome must be unchanged.
        let mut db_extended = base_db.clone();
        db_extended.push(extra);
        let after_db = evaluate_effective(&id, a, &s, &d, &yaml_perms, &db_extended);
        prop_assert_eq!(&before, &after_db, "appending non-matching DB grant changed outcome");
    }
}
