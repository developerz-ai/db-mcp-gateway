//! DB-grant aware evaluation with symmetric YAML/DB merging (#49).
//!
//! `can_see_server_effective` and `evaluate_effective` extend the YAML-only
//! versions with a per-identity DB-grant slice. Both sources merge
//! most-restrictively — neither is privileged. This module encapsulates
//! that logic and its tests.
//!
//! Resolver-level safety proofs live in `effective_proptests` (#50, test-only module).

use crate::auth::Identity;
use crate::config::{Action, Constraints, Grant, Permission, Server};

use super::{Decision, grant_applies, merge};

/// `can_see_server` extended with a per-identity DB-grant slice (#49).
/// Symmetric merge: a server is visible if YAML *or* DB grants make it so.
pub fn can_see_server_effective(
    identity: &Identity,
    server: &Server,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> bool {
    super::can_see_server(identity, server, yaml_permissions)
        || db_grants_for_identity
            .iter()
            .any(|grant| super::grant_can_see(grant, server))
}

/// `evaluate` extended with a per-identity DB-grant slice (#49).
///
/// YAML grants are group-keyed; DB grants are user-keyed and pre-resolved to
/// this `identity` by the loader, so they bypass the group filter. Both sets
/// feed the same most-restrictive merge — there is no priority between them.
pub fn evaluate_effective(
    identity: &Identity,
    action: Action,
    server: &str,
    database: &str,
    yaml_permissions: &[Permission],
    db_grants_for_identity: &[Grant],
) -> Decision {
    let yaml_matches = yaml_permissions
        .iter()
        .filter(|p| identity.groups.iter().any(|g| g == &p.group))
        .flat_map(|p| p.grants.iter())
        .filter(|g| grant_applies(g, action, server, database));

    let db_matches = db_grants_for_identity
        .iter()
        .filter(|g| grant_applies(g, action, server, database));

    let mut merged_some = false;
    let mut merged = Constraints::default();
    for c in yaml_matches.chain(db_matches).map(|g| &g.constraints) {
        merged = merge(&merged, c);
        merged_some = true;
    }
    if merged_some {
        Decision::Allow {
            constraints: merged,
        }
    } else {
        Decision::Deny
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
            issued_at: chrono::Utc::now(),
        }
    }

    fn database(name: &str) -> Database {
        Database {
            name: name.to_string(),
            role: "ro".to_string(),
            password: Password::Literal("pw".into()),
            description: String::new(),
            auth_database: None,
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

    fn grant(server: &str, database: &str, action: Action) -> Grant {
        Grant {
            server: server.to_string(),
            database: database.to_string(),
            action,
            constraints: Constraints::default(),
        }
    }

    fn grant_with(server: &str, database: &str, action: Action, constraints: Constraints) -> Grant {
        Grant {
            server: server.to_string(),
            database: database.to_string(),
            action,
            constraints,
        }
    }

    fn permission(group: &str, server: &str, action: Action) -> Permission {
        Permission {
            group: group.to_string(),
            grants: vec![grant(server, "*", action)],
        }
    }

    // --- can_see_server_effective ---

    #[test]
    fn db_grant_alone_makes_server_visible() {
        let id = identity(&["nobody"]);
        let server = server("prod");
        let db_grants = vec![grant("prod", "app", Action::QueryRead)];
        assert!(can_see_server_effective(&id, &server, &[], &db_grants));
    }

    #[test]
    fn db_grant_respects_database_existence() {
        let id = identity(&["nobody"]);
        let server = server("prod"); // databases = [app]
        let db_grants = vec![grant("prod", "missing", Action::QueryRead)];
        assert!(!can_see_server_effective(&id, &server, &[], &db_grants));
    }

    #[test]
    fn yaml_and_db_grants_merge_visibly() {
        let id = identity(&["engineers"]);
        let server = server("prod");
        let yaml_perms = vec![permission("engineers", "staging", Action::QueryRead)];
        let db_grants = vec![grant("prod", "app", Action::QueryRead)];
        // Visible because DB grant covers prod, even though YAML doesn't.
        assert!(can_see_server_effective(
            &id,
            &server,
            &yaml_perms,
            &db_grants
        ));
    }

    // --- evaluate_effective ---

    #[test]
    fn db_grant_alone_grants_access() {
        let id = identity(&["nobody"]);
        let db_grants = vec![grant("prod", "app", Action::QueryRead)];
        let decision = evaluate_effective(&id, Action::QueryRead, "prod", "app", &[], &db_grants);
        assert_eq!(
            decision,
            Decision::Allow {
                constraints: Constraints::default()
            }
        );
    }

    #[test]
    fn db_grant_respects_action_hierarchy() {
        let id = identity(&["nobody"]);
        let db_grants = vec![grant("prod", "app", Action::SchemaRead)];
        // SchemaRead grant doesn't cover QueryRead.
        let decision = evaluate_effective(&id, Action::QueryRead, "prod", "app", &[], &db_grants);
        assert_eq!(decision, Decision::Deny);
    }

    #[test]
    fn yaml_and_db_grants_merge_constraints() {
        let id = identity(&["oncall"]);
        let yaml_perms = vec![Permission {
            group: "oncall".to_string(),
            grants: vec![grant_with(
                "prod",
                "app",
                Action::QueryRead,
                Constraints {
                    require_reason: false,
                    row_limit: Some(10_000),
                    statement_timeout_ms: None,
                },
            )],
        }];
        let db_grants = vec![grant_with(
            "prod",
            "app",
            Action::QueryRead,
            Constraints {
                require_reason: true,
                row_limit: Some(1_000),
                statement_timeout_ms: Some(5_000),
            },
        )];
        let decision = evaluate_effective(
            &id,
            Action::QueryRead,
            "prod",
            "app",
            &yaml_perms,
            &db_grants,
        );
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

    #[test]
    fn evaluate_merges_yaml_and_db_most_restrictive() {
        let id = identity(&["engineers"]);
        let yaml_perms = vec![Permission {
            group: "engineers".to_string(),
            grants: vec![grant_with(
                "*",
                "*",
                Action::QueryRead,
                Constraints {
                    require_reason: false,
                    row_limit: Some(50_000),
                    statement_timeout_ms: Some(30_000),
                },
            )],
        }];
        let db_grants = vec![grant_with(
            "prod",
            "app",
            Action::QueryRead,
            Constraints {
                require_reason: false,
                row_limit: Some(100),
                statement_timeout_ms: Some(1_000),
            },
        )];
        let decision = evaluate_effective(
            &id,
            Action::QueryRead,
            "prod",
            "app",
            &yaml_perms,
            &db_grants,
        );
        assert_eq!(
            decision,
            Decision::Allow {
                constraints: Constraints {
                    require_reason: false,
                    row_limit: Some(100),              // most restrictive
                    statement_timeout_ms: Some(1_000), // most restrictive
                }
            }
        );
    }
}
