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

/// Returns true iff `identity` has at least one grant on `server` — across
/// any database, any action. Used to filter the `list_servers` output so a
/// user never learns of a server they have zero grants on.
pub fn can_see_server(
    identity: &Identity,
    server: &Server,
    permissions: &[Permission],
) -> bool {
    permissions
        .iter()
        .filter(|perm| identity.groups.iter().any(|g| g == &perm.group))
        .flat_map(|perm| perm.grants.iter())
        .any(|grant| grant.server == "*" || grant.server == server.name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SessionId;
    use crate::config::{Action, Grant, Permission, ServerKind, Tls};

    fn identity(groups: &[&str]) -> Identity {
        Identity {
            session_id: SessionId::new(),
            user_sub: "test-sub".to_string(),
            user_email: "test@example.com".to_string(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
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
            databases: vec![],
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
}
