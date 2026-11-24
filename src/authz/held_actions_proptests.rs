//! `held_actions` is what the discovery tools (`list_databases`,
//! `list_servers`, `whoami`) report. These properties pin it to
//! `evaluate_effective`, the check every tool call runs: an action is listed
//! iff evaluation allows it, with exactly the constraints evaluation
//! enforces for it — never a merged-across-actions approximation.

use super::super::proptest_support::{TEST_GROUP, any_grants, as_yaml_for, identity_in};
use super::{ALL_ACTIONS, held_actions};
use crate::authz::{Decision, evaluate_effective};
use proptest::prelude::*;

/// Names `proptest_support::any_grant` draws servers/databases from, plus
/// one it never does.
fn any_target() -> impl Strategy<Value = (String, String)> {
    (
        prop_oneof![Just("prod"), Just("staging"), Just("absent")],
        prop_oneof![Just("app"), Just("billing"), Just("absent")],
    )
        .prop_map(|(s, d)| (s.to_string(), d.to_string()))
}

proptest! {
    #[test]
    fn held_actions_equal_evaluation_for_every_action(
        yaml in any_grants(),
        db in any_grants(),
        target in any_target(),
    ) {
        let id = identity_in(TEST_GROUP);
        let (server, database) = target;
        let perms = as_yaml_for(TEST_GROUP, yaml);
        let held = held_actions(&id, &server, &database, &perms, &db);
        for action in ALL_ACTIONS {
            let reported = held.iter().find(|h| h.action == action);
            match evaluate_effective(&id, action, &server, &database, &perms, &db) {
                Decision::Allow { constraints } => {
                    prop_assert_eq!(reported.map(|h| &h.constraints), Some(&constraints));
                }
                Decision::Deny => prop_assert!(reported.is_none(), "{:?} listed but denied", action),
            }
        }
    }

    /// An identity outside every group holds nothing, whatever the YAML says.
    #[test]
    fn identity_outside_the_group_holds_nothing(
        yaml in any_grants(),
        target in any_target(),
    ) {
        let id = identity_in("not-the-group");
        let (server, database) = target;
        let perms = as_yaml_for(TEST_GROUP, yaml);
        prop_assert!(held_actions(&id, &server, &database, &perms, &[]).is_empty());
    }
}
