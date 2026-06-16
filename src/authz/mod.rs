//! Authorization: group-grant evaluation for MCP tool calls.
//!
//! `can_see_server` (used by `list_servers`) gives a binary visible/hidden
//! answer. `evaluate(action, server, database)` is the canonical per-call
//! check — used by every action-gated tool from #4 onward. It returns either
//! `Decision::Allow { constraints }` (merged most-restrictively across every
//! matching grant) or `Decision::Deny`.
//!
//! `evaluate_effective` / `can_see_server_effective` (since #49) fold a
//! per-identity slice of DB-loaded grants into the same merge engine. The
//! YAML and DB sources are symmetric — neither source is privileged, the
//! most-restrictive constraint always wins on overlap.
//!
//! Security-required (see CLAUDE.md). The contract: a request is allowed iff
//! *some* grant matches. Absence of a matching grant denies — no implicit
//! upgrade from group membership alone (spec 06 §Evaluation). Most-restrictive
//! merging means being in two groups never *upgrades* your access.

pub mod cache;
pub mod effective;
pub mod loader;

pub use cache::PermissionsCache;
pub use effective::{can_see_server_effective, evaluate_effective};
pub use loader::{LoadError, load_db_grants_for};

use crate::auth::Identity;
use crate::config::{Action, Constraints, Grant, Permission, Server};

/// Outcome of an `evaluate` call. `Allow` carries the merged constraints the
/// executor must enforce (statement timeout, row limit, reason requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { constraints: Constraints },
    Deny,
}

/// Returns true iff `identity` has at least one grant that can actually apply
/// to `server` — i.e. the grant targets this server (or `*`) AND names a
/// database that exists on it (or `*`). Used to filter the `list_servers`
/// output so a user never learns of a server they have zero usable grants on.
///
/// A grant whose database doesn't exist on the matched server is treated as
/// non-applicable. Otherwise a stale grant on `database: app-typo` would still
/// reveal the server in `list_servers`, even though no real action against it
/// could ever succeed.
pub fn can_see_server(identity: &Identity, server: &Server, permissions: &[Permission]) -> bool {
    permissions
        .iter()
        .filter(|perm| identity.groups.iter().any(|g| g == &perm.group))
        .flat_map(|perm| perm.grants.iter())
        .any(|grant| grant_can_see(grant, server))
}

/// Per-call authz check. The action passed is what the *tool* needs; matching
/// grants are those whose action *includes* the requested one (see
/// `Action::includes` — `query_write` ⊇ `query_read` ⊇ `schema_read`).
pub fn evaluate(
    identity: &Identity,
    action: Action,
    server: &str,
    database: &str,
    permissions: &[Permission],
) -> Decision {
    evaluate_effective(identity, action, server, database, permissions, &[])
}

/// Helper: check if a grant allows viewing a server (used by both
/// can_see_server variants). Verifies server name matches and database
/// exists on that server.
pub fn grant_can_see(grant: &Grant, server: &Server) -> bool {
    let server_match = grant.server == "*" || grant.server == server.name;
    if !server_match {
        return false;
    }
    grant.database == "*" || server.databases.iter().any(|db| db.name == grant.database)
}

/// Helper: check if a grant applies to an action on a server/database pair.
/// Used by both evaluate variants.
pub fn grant_applies(grant: &Grant, action: Action, server: &str, database: &str) -> bool {
    (grant.server == "*" || grant.server == server)
        && (grant.database == "*" || grant.database == database)
        && grant.action.includes(action)
}

/// Merge two `Constraints` most-restrictively. Pure — same inputs, same
/// output — so property tests can hammer it freely.
///
/// Rule per spec 06: lowest `row_limit` wins, lowest `statement_timeout_ms`
/// wins, `require_reason: true` always wins. `None` on either side means
/// "no constraint from this side" — the other side's value carries through.
pub fn merge(a: &Constraints, b: &Constraints) -> Constraints {
    Constraints {
        require_reason: a.require_reason || b.require_reason,
        row_limit: min_option(a.row_limit, b.row_limit),
        statement_timeout_ms: min_option(a.statement_timeout_ms, b.statement_timeout_ms),
    }
}

fn min_option<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SessionId;
    use crate::config::{Database, Password, ServerKind, Tls};

    fn identity(groups: &[&str]) -> Identity {
        Identity {
            session_id: SessionId::new(),
            user_sub: "test-sub".to_string(),
            user_email: "test@example.com".to_string(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    fn database(name: &str) -> Database {
        Database {
            name: name.to_string(),
            role: "ro".to_string(),
            password: Password::Literal("pw".to_string()),
            description: String::new(),
        }
    }

    fn server(name: &str) -> Server {
        Server {
            name: name.to_string(),
            kind: ServerKind::Postgres,
            description: String::new(),
            host: "h".to_string(),
            port: 5432,
            tls: Tls::Required,
            databases: vec![database("app")],
        }
    }

    fn permission(group: &str, server: &str, action: Action) -> Permission {
        Permission {
            group: group.to_string(),
            grants: vec![Grant {
                server: server.to_string(),
                database: "*".to_string(),
                action,
                constraints: Constraints::default(),
            }],
        }
    }

    fn permission_db(group: &str, server: &str, database: &str, action: Action) -> Permission {
        Permission {
            group: group.to_string(),
            grants: vec![Grant {
                server: server.to_string(),
                database: database.to_string(),
                action,
                constraints: Constraints::default(),
            }],
        }
    }

    fn permission_with(
        group: &str,
        server: &str,
        database: &str,
        action: Action,
        constraints: Constraints,
    ) -> Permission {
        Permission {
            group: group.to_string(),
            grants: vec![Grant {
                server: server.to_string(),
                database: database.to_string(),
                action,
                constraints,
            }],
        }
    }

    // --- can_see_server -----------------------------------------------------

    #[test]
    fn user_in_no_matching_group_cant_see() {
        let id = identity(&["finance"]);
        let prod = server("prod");
        let perms = vec![permission("engineers", "prod", Action::QueryRead)];
        assert!(!can_see_server(&id, &prod, &perms));
    }

    #[test]
    fn user_in_named_grant_sees_server() {
        let id = identity(&["engineers"]);
        let prod = server("prod");
        let perms = vec![permission("engineers", "prod", Action::SchemaRead)];
        assert!(can_see_server(&id, &prod, &perms));
    }

    #[test]
    fn user_in_named_grant_doesnt_see_other_server() {
        let id = identity(&["engineers"]);
        let staging = server("staging");
        let perms = vec![permission("engineers", "prod", Action::QueryRead)];
        assert!(!can_see_server(&id, &staging, &perms));
    }

    #[test]
    fn wildcard_server_grant_covers_any_server() {
        let id = identity(&["engineers"]);
        let perms = vec![permission("engineers", "*", Action::SchemaRead)];
        assert!(can_see_server(&id, &server("anything"), &perms));
        assert!(can_see_server(&id, &server("else"), &perms));
    }

    #[test]
    fn empty_permissions_denies_everyone() {
        let id = identity(&["engineers"]);
        assert!(!can_see_server(&id, &server("prod"), &[]));
    }

    #[test]
    fn grant_with_unknown_database_does_not_grant_visibility() {
        let id = identity(&["engineers"]);
        let prod = server("prod"); // databases = [app]
        let perms = vec![permission_db(
            "engineers",
            "prod",
            "missing",
            Action::QueryRead,
        )];
        assert!(!can_see_server(&id, &prod, &perms));
    }

    #[test]
    fn grant_with_existing_database_grants_visibility() {
        let id = identity(&["engineers"]);
        let prod = server("prod"); // databases = [app]
        let perms = vec![permission_db("engineers", "prod", "app", Action::QueryRead)];
        assert!(can_see_server(&id, &prod, &perms));
    }

    #[test]
    fn wildcard_server_still_requires_db_match() {
        let id = identity(&["engineers"]);
        let prod = server("prod"); // databases = [app]
        let perms = vec![permission_db(
            "engineers",
            "*",
            "missing",
            Action::QueryRead,
        )];
        assert!(!can_see_server(&id, &prod, &perms));

        let perms = vec![permission_db("engineers", "*", "app", Action::QueryRead)];
        assert!(can_see_server(&id, &prod, &perms));
    }

    // --- evaluate -----------------------------------------------------------

    #[test]
    fn evaluate_deny_when_no_group_matches() {
        let id = identity(&["finance"]);
        let perms = vec![permission("engineers", "prod", Action::QueryRead)];
        assert_eq!(
            evaluate(&id, Action::QueryRead, "prod", "app", &perms),
            Decision::Deny
        );
    }

    #[test]
    fn evaluate_deny_when_grant_action_too_weak() {
        // schema_read grant cannot cover a query_read request.
        let id = identity(&["engineers"]);
        let perms = vec![permission_db(
            "engineers",
            "prod",
            "app",
            Action::SchemaRead,
        )];
        assert_eq!(
            evaluate(&id, Action::QueryRead, "prod", "app", &perms),
            Decision::Deny
        );
    }

    #[test]
    fn evaluate_allows_when_grant_action_includes() {
        // query_write ⊇ query_read ⊇ schema_read.
        let id = identity(&["engineers"]);
        let perms = vec![permission_db(
            "engineers",
            "prod",
            "app",
            Action::QueryWrite,
        )];
        assert_eq!(
            evaluate(&id, Action::QueryRead, "prod", "app", &perms),
            Decision::Allow {
                constraints: Constraints::default()
            }
        );
    }

    #[test]
    fn evaluate_merges_constraints_most_restrictive() {
        let id = identity(&["engineers", "oncall"]);
        let perms = vec![
            permission_with(
                "engineers",
                "prod",
                "*",
                Action::QueryRead,
                Constraints {
                    require_reason: false,
                    row_limit: Some(10_000),
                    statement_timeout_ms: None,
                },
            ),
            permission_with(
                "oncall",
                "prod",
                "*",
                Action::QueryRead,
                Constraints {
                    require_reason: true,
                    row_limit: Some(1_000),
                    statement_timeout_ms: Some(5_000),
                },
            ),
        ];
        let decision = evaluate(&id, Action::QueryRead, "prod", "app", &perms);
        assert_eq!(
            decision,
            Decision::Allow {
                constraints: Constraints {
                    require_reason: true,
                    row_limit: Some(1_000),
                    statement_timeout_ms: Some(5_000),
                }
            }
        );
    }
}

#[cfg(test)]
mod proptests {
    //! Property tests for `merge`. The whole point of most-restrictive merging
    //! is that no permutation of grants ever lets a user *upgrade* their
    //! access — codify that property here so future refactors can't quietly
    //! regress it.

    use super::*;
    use proptest::prelude::*;

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
}
