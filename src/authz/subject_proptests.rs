//! `user:` subjects (plan 101 O13) join the same per-action most-restrictive
//! merge as group blocks: a user grant can add access the user's groups lack,
//! but where both match the same action the merged constraints are the
//! tightest of the two, and a user block never reaches another subject or a
//! service identity.

use proptest::prelude::*;

use super::proptest_support::{TEST_GROUP, any_grants, any_request, identity_in};
use super::{Decision, evaluate, merge};
use crate::auth::IdentityKind;
use crate::config::Permission;
use crate::config::schema::Subject;

fn blocks(
    group_grants: Vec<crate::config::Grant>,
    user_grants: Vec<crate::config::Grant>,
) -> Vec<Permission> {
    vec![
        Permission {
            subject: Subject::Group(TEST_GROUP.to_string()),
            grants: group_grants,
        },
        Permission {
            subject: Subject::User("test-sub".to_string()),
            grants: user_grants,
        },
    ]
}

fn only(subject: Subject, grants: Vec<crate::config::Grant>) -> Vec<Permission> {
    vec![Permission { subject, grants }]
}

proptest! {
    /// The combined decision per action is exactly the merge of what the
    /// group block and the user block allow on their own.
    #[test]
    fn user_and_group_grants_merge_most_restrictive_per_action(
        group in any_grants(),
        user in any_grants(),
        (server, database, action) in any_request(),
    ) {
        let id = identity_in(TEST_GROUP);
        let combined = evaluate(&id, action, &server, &database, &blocks(group.clone(), user.clone()));
        let by_group = evaluate(&id, action, &server, &database,
            &only(Subject::Group(TEST_GROUP.to_string()), group));
        let by_user = evaluate(&id, action, &server, &database,
            &only(Subject::User("test-sub".to_string()), user));
        let expected = match (by_group, by_user) {
            (Decision::Deny, Decision::Deny) => Decision::Deny,
            (Decision::Allow { constraints }, Decision::Deny)
            | (Decision::Deny, Decision::Allow { constraints }) => Decision::Allow { constraints },
            (Decision::Allow { constraints: a }, Decision::Allow { constraints: b }) => {
                Decision::Allow { constraints: merge(&a, &b) }
            }
        };
        prop_assert_eq!(combined, expected);
    }

    /// A user block is invisible to every other subject, and to a service
    /// identity even when its name equals the block's subject.
    #[test]
    fn user_block_matches_only_that_sso_subject(
        user in any_grants(),
        (server, database, action) in any_request(),
    ) {
        let perms = only(Subject::User("test-sub".to_string()), user);
        let mut other = identity_in(TEST_GROUP);
        other.user_sub = "someone-else".to_string();
        prop_assert_eq!(evaluate(&other, action, &server, &database, &perms), Decision::Deny);
        let mut service = identity_in(TEST_GROUP);
        service.kind = IdentityKind::Service;
        prop_assert_eq!(evaluate(&service, action, &server, &database, &perms), Decision::Deny);
    }
}
