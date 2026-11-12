//! Property tests for `merge`. The whole point of most-restrictive merging
//! is that no permutation of grants ever lets a user *upgrade* their
//! access — codify that property here so future refactors can't quietly
//! regress it.

use proptest::prelude::*;

use super::proptest_support::any_constraints;
use super::*;

/// `min_option` is the meaning of "most restrictive" for `Option<u32>`:
/// any constraint set on either side beats no constraint; otherwise the
/// smaller value wins.
fn min_option_naive(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

proptest! {
    #[test]
    fn merge_is_commutative(a in any_constraints(), b in any_constraints()) {
        prop_assert_eq!(merge(&a, &b), merge(&b, &a));
    }

    #[test]
    fn merge_with_default_is_identity(a in any_constraints()) {
        prop_assert_eq!(merge(&a, &Constraints::default()), a.clone());
        prop_assert_eq!(merge(&Constraints::default(), &a), a);
    }

    #[test]
    fn merge_is_associative(a in any_constraints(), b in any_constraints(), c in any_constraints()) {
        let left = merge(&merge(&a, &b), &c);
        let right = merge(&a, &merge(&b, &c));
        prop_assert_eq!(left, right);
    }

    #[test]
    fn folded_merge_matches_pointwise_minimum(grants in proptest::collection::vec(any_constraints(), 1..8)) {
        let merged = grants.iter().fold(Constraints::default(), |acc, c| merge(&acc, c));

        let expected_row_limit = grants.iter()
            .map(|g| g.row_limit)
            .fold(None, min_option_naive);
        let expected_timeout = grants.iter()
            .map(|g| g.statement_timeout_ms)
            .fold(None, min_option_naive);
        let expected_reason = grants.iter().any(|g| g.require_reason);

        prop_assert_eq!(merged.row_limit, expected_row_limit);
        prop_assert_eq!(merged.statement_timeout_ms, expected_timeout);
        prop_assert_eq!(merged.require_reason, expected_reason);
    }

    /// The headline safety property: adding a permissive grant to a set of
    /// restrictive ones never *raises* the limits or relaxes
    /// `require_reason`. Belonging to a second group must never be an
    /// upgrade.
    #[test]
    fn adding_a_grant_never_relaxes(initial in any_constraints(), extra in any_constraints()) {
        let with_extra = merge(&initial, &extra);
        // row_limit / timeout: with_extra ≤ initial (when both set);
        // if initial was None, any value is "more restrictive" so the
        // invariant is trivially satisfied.
        if let (Some(a), Some(b)) = (initial.row_limit, with_extra.row_limit) {
            prop_assert!(b <= a);
        }
        if let (Some(a), Some(b)) = (initial.statement_timeout_ms, with_extra.statement_timeout_ms) {
            prop_assert!(b <= a);
        }
        // require_reason: once true, always true.
        if initial.require_reason {
            prop_assert!(with_extra.require_reason);
        }
    }
}
