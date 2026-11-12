//! Example-based tests for `can_see_server`, `evaluate` and `merge`.

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
        kind: crate::auth::IdentityKind::Sso,
    }
}

fn database(name: &str) -> Database {
    Database {
        name: name.to_string(),
        role: "ro".to_string(),
        password: Password::Literal("pw".into()),
        description: String::new(),
        auth_database: None,
        pool: None,
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
        tls_ca_file: None,
        pool: None,
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
