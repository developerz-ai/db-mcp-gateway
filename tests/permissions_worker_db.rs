//! Spec test for the shipped `config/permissions.yml`.
//!
//! Catches drift if anyone edits the YAML without thinking through who can
//! see what. Loads the actual file the infra stack PR (#17) deploys, then
//! evaluates `(group, server, db, action)` for every cell we care about.
//!
//! Issue #19. Per-dev DB ownership is deferred — collective group ownership
//! is the v1 contract.

use std::path::PathBuf;

use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::authz::{Decision, evaluate};
use db_mcp_gateway::config::{Action, ConfigFile};

fn permissions_yml() -> ConfigFile {
    // Skip secret resolution — the file ships ${FILE:…} refs that only exist
    // inside the deployed pod. Structural validity + authz behavior is what
    // the test asserts; secret-resolution coverage lives in
    // tests/secret_refs.rs.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/permissions.yml");
    ConfigFile::from_file(&path).expect("config/permissions.yml must parse")
}

fn identity_in(group: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: format!("test-{group}"),
        user_email: format!("{group}@developerz.ai"),
        groups: vec![group.to_string()],
    }
}

const APP_DBS: &[&str] = &["discord_server", "legaldiligencemedellin"];
const INFRA_DBS: &[&str] = &["zitadel", "vaultwarden"];

#[test]
fn devs_can_query_read_every_app_db() {
    let cfg = permissions_yml();
    let id = identity_in("devs");
    for db in APP_DBS {
        let decision = evaluate(&id, Action::QueryRead, "worker-db", db, &cfg.permissions);
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "devs must see {db}, got {decision:?}"
        );
    }
}

#[test]
fn devs_cannot_touch_infra_dbs() {
    let cfg = permissions_yml();
    let id = identity_in("devs");
    for db in INFRA_DBS {
        assert_eq!(
            evaluate(&id, Action::SchemaRead, "worker-db", db, &cfg.permissions),
            Decision::Deny,
            "devs must NOT see infra DB {db}"
        );
    }
}

#[test]
fn devops_matches_devs_in_v1() {
    let cfg = permissions_yml();
    let devs = evaluate(
        &identity_in("devs"),
        Action::QueryRead,
        "worker-db",
        "discord_server",
        &cfg.permissions,
    );
    let devops = evaluate(
        &identity_in("devops"),
        Action::QueryRead,
        "worker-db",
        "discord_server",
        &cfg.permissions,
    );
    assert_eq!(devs, devops);
}

#[test]
fn cto_can_query_read_every_listed_db() {
    let cfg = permissions_yml();
    let id = identity_in("cto");
    for db in APP_DBS.iter().chain(INFRA_DBS.iter()) {
        let decision = evaluate(&id, Action::QueryRead, "worker-db", db, &cfg.permissions);
        assert!(
            matches!(decision, Decision::Allow { .. }),
            "cto must see {db}, got {decision:?}"
        );
    }
}

#[test]
fn nobody_gets_query_write_in_v1() {
    let cfg = permissions_yml();
    for group in ["devs", "devops", "cto"] {
        let id = identity_in(group);
        for db in APP_DBS.iter().chain(INFRA_DBS.iter()) {
            assert_eq!(
                evaluate(&id, Action::QueryWrite, "worker-db", db, &cfg.permissions),
                Decision::Deny,
                "{group} must NOT have query_write on {db}"
            );
        }
    }
}

#[test]
fn caps_carry_through_to_executor() {
    // statement_timeout_ms + row_limit must reach the exec layer; if the YAML
    // drops them, the gateway happily runs unbounded queries.
    let cfg = permissions_yml();
    let decision = evaluate(
        &identity_in("devs"),
        Action::QueryRead,
        "worker-db",
        "discord_server",
        &cfg.permissions,
    );
    let Decision::Allow { constraints } = decision else {
        panic!("expected Allow, got {decision:?}");
    };
    assert_eq!(constraints.row_limit, Some(10_000));
    assert_eq!(constraints.statement_timeout_ms, Some(30_000));
    assert!(!constraints.require_reason);
}

#[test]
fn unknown_group_denied_everywhere() {
    let cfg = permissions_yml();
    let id = identity_in("interns");
    for db in APP_DBS.iter().chain(INFRA_DBS.iter()) {
        assert_eq!(
            evaluate(&id, Action::SchemaRead, "worker-db", db, &cfg.permissions),
            Decision::Deny
        );
    }
}
