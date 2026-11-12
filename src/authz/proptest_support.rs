//! Strategies and predicates shared by the authz property tests.

use proptest::prelude::*;

use crate::auth::{Identity, SessionId};
use crate::config::{Action, Constraints, Grant, Permission};

pub(super) const TEST_GROUP: &str = "g";

pub(super) fn any_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::SchemaRead),
        Just(Action::QueryRead),
        Just(Action::QueryWrite),
        Just(Action::HistoryRead),
    ]
}

/// Includes `Some(0)` on both bounds: zero is the tightest value, never "unset".
pub(super) fn any_constraints() -> impl Strategy<Value = Constraints> {
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

pub(super) fn any_grant() -> impl Strategy<Value = Grant> {
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

pub(super) fn any_grants() -> impl Strategy<Value = Vec<Grant>> {
    proptest::collection::vec(any_grant(), 0..6)
}

/// Concrete `(server, database, action)` request — uses the non-wildcard
/// alphabet, since wildcards on the *request* side never appear in real
/// dispatch.
pub(super) fn any_request() -> impl Strategy<Value = (String, String, Action)> {
    let req_server = prop_oneof![Just("prod".to_string()), Just("staging".to_string())];
    let req_db = prop_oneof![Just("app".to_string()), Just("billing".to_string())];
    (req_server, req_db, any_action())
}

pub(super) fn identity_in(group: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: "test-sub".to_string(),
        user_email: "test@example.com".to_string(),
        groups: vec![group.to_string()],
        issued_at: chrono::Utc::now(),
        kind: crate::auth::IdentityKind::Sso,
    }
}

/// Wrap a flat `Vec<Grant>` into one `Permission` keyed on `group`.
pub(super) fn as_yaml_for(group: &str, grants: Vec<Grant>) -> Vec<Permission> {
    vec![Permission {
        group: group.to_string(),
        grants,
    }]
}

/// True iff, field-wise, `a` is no more permissive than `b`:
/// `require_reason: true` is stricter than `false`; a lower bound is
/// stricter; `Some(n)` is stricter than `None` (a bound binds).
pub(super) fn no_more_permissive_than(a: &Constraints, b: &Constraints) -> bool {
    let reason_ok = a.require_reason || !b.require_reason;
    bound_ok(a.row_limit, b.row_limit)
        && bound_ok(a.statement_timeout_ms, b.statement_timeout_ms)
        && reason_ok
}

fn bound_ok(a: Option<u32>, b: Option<u32>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a <= b,
        (Some(_), None) | (None, None) => true,
        (None, Some(_)) => false,
    }
}
