//! Property tests for [`ConstraintsPatch`]: a PATCH can never loosen a
//! constraint it did not name, and the JSON a client sends is exactly the
//! patch the handler applies.

use proptest::prelude::*;
use serde_json::{Map, Value};

use super::patch::ConstraintsPatch;
use super::proptest_support::{any_constraints, no_more_permissive_than};
use crate::config::Constraints;

/// Tri-state per key: absent, explicit `null`, or a value.
fn tri<T: std::fmt::Debug + Clone + 'static>(
    value: impl Strategy<Value = T> + 'static,
) -> impl Strategy<Value = Option<Option<T>>> {
    prop_oneof![
        Just(None),
        Just(Some(None)),
        value.prop_map(|v| Some(Some(v))),
    ]
}

fn any_patch() -> impl Strategy<Value = ConstraintsPatch> {
    (
        tri(any::<bool>()),
        tri(0u32..=1_000_000),
        tri(0u32..=600_000),
    )
        .prop_map(
            |(require_reason, row_limit, statement_timeout_ms)| ConstraintsPatch {
                require_reason,
                row_limit,
                statement_timeout_ms,
            },
        )
}

/// The wire form: an absent key is left out of the object entirely.
fn to_json(p: &ConstraintsPatch) -> Value {
    fn put<T: serde::Serialize>(m: &mut Map<String, Value>, key: &str, v: &Option<Option<T>>) {
        if let Some(inner) = v {
            m.insert(key.to_string(), serde_json::json!(inner));
        }
    }
    let mut m = Map::new();
    put(&mut m, "require_reason", &p.require_reason);
    put(&mut m, "row_limit", &p.row_limit);
    put(&mut m, "statement_timeout_ms", &p.statement_timeout_ms);
    Value::Object(m)
}

proptest! {
    /// Absent / `null` / value survive the JSON boundary distinctly — the
    /// difference between "keep" and "clear" is never lost in parsing.
    #[test]
    fn json_round_trip_preserves_every_key_state(p in any_patch()) {
        let parsed: ConstraintsPatch = serde_json::from_value(to_json(&p)).unwrap();
        prop_assert_eq!(parsed, p);
    }

    /// **The headline property.** Every key the patch does not name keeps
    /// its stored value — whatever else the patch does.
    #[test]
    fn unnamed_keys_are_untouched(current in any_constraints(), p in any_patch()) {
        let out = p.apply(&current);
        if p.require_reason.is_none() {
            prop_assert_eq!(out.require_reason, current.require_reason);
        }
        if p.row_limit.is_none() {
            prop_assert_eq!(out.row_limit, current.row_limit);
        }
        if p.statement_timeout_ms.is_none() {
            prop_assert_eq!(out.statement_timeout_ms, current.statement_timeout_ms);
        }
    }

    #[test]
    fn empty_patch_is_identity(current in any_constraints()) {
        let p = ConstraintsPatch::default();
        prop_assert!(p.is_empty());
        prop_assert_eq!(p.apply(&current), current);
    }

    #[test]
    fn apply_is_idempotent(current in any_constraints(), p in any_patch()) {
        let once = p.apply(&current);
        prop_assert_eq!(p.apply(&once), once);
    }

    /// A patch whose every value is set (not cleared) and at least as strict
    /// as the stored one can only tighten — most restrictive wins.
    #[test]
    fn tightening_patch_never_loosens(current in any_constraints(), target in any_constraints()) {
        let tighter = Constraints {
            require_reason: current.require_reason || target.require_reason,
            row_limit: super::merge(&current, &target).row_limit,
            statement_timeout_ms: super::merge(&current, &target).statement_timeout_ms,
        };
        let p = ConstraintsPatch {
            require_reason: Some(Some(tighter.require_reason)),
            row_limit: Some(tighter.row_limit),
            statement_timeout_ms: Some(tighter.statement_timeout_ms),
        };
        prop_assert!(no_more_permissive_than(&p.apply(&current), &current));
    }

    /// An unknown key is a 400, never a silently ignored typo.
    #[test]
    fn unknown_key_is_rejected(p in any_patch()) {
        let mut v = to_json(&p);
        v.as_object_mut().unwrap().insert("row_limt".into(), serde_json::json!(1));
        prop_assert!(serde_json::from_value::<ConstraintsPatch>(v).is_err());
    }
}
