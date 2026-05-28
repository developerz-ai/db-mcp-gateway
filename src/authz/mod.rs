//! Authorization: group-grant evaluation for MCP tool calls.
//!
//! For #3 only `can_see_server` is wired — the visibility check `list_servers`
//! needs. The fuller `evaluate(action, server, database)` API and
//! constraint-merge logic (most-restrictive-wins) arrive with the
//! action-gated tools (#4-#8). Keeping it concrete now per CLAUDE.md.
//!
//! Security-required (see CLAUDE.md). The contract: a request is allowed iff
//! *some* grant matches. Absence of a matching grant denies — no implicit
//! upgrade from group membership alone (spec 06 §Evaluation).

use crate::auth::Identity;
use crate::config::{Permission, Server};

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
        .any(|grant| {
            let server_match = grant.server == "*" || grant.server == server.name;
            if !server_match {
                return false;
            }
            grant.database == "*" || server.databases.iter().any(|db| db.name == grant.database)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SessionId;
    use crate::config::{Action, Database, Grant, Password, Permission, ServerKind, Tls};

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
            }],
        }
    }

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

    /// A grant naming a database that doesn't exist on the matched server is
    /// non-applicable; visibility must not leak the server.
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
}
