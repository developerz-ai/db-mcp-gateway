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
    //
    // Audit-row assertions are intentionally skipped throughout this file:
    // tests call `evaluate(...)` directly against the authz layer in isolation,
    // which has no audit integration yet (the isolated-layer exception in the
    // testing guidelines). Audit coverage lives in the tool-dispatch tests
    // where the wire path actually emits audit rows.
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
    // Asserts the full query_read ⇒ schema_read implication (spec 06): the
    // implied schema_read path must be Allow for every app DB the grant lists.
    let cfg = permissions_yml();
    let id = identity_in("devs");
    for db in APP_DBS {
        for action in [Action::QueryRead, Action::SchemaRead] {
            let decision = evaluate(&id, action, "worker-db", db, &cfg.permissions);
            assert!(
                matches!(decision, Decision::Allow { .. }),
                "devs must see {db} for {action:?}, got {decision:?}"
            );
        }
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
fn devops_matches_devs_on_every_app_db() {
    // Spot-checking one DB hides a missing-grant regression on the others.
    // Iterate every APP_DBS entry under both QueryRead and the implied
    // SchemaRead so legaldiligencemedellin (or any future addition) can't
    // silently drop out of the devops grant.
    let cfg = permissions_yml();
    let devs_id = identity_in("devs");
    let devops_id = identity_in("devops");
    for db in APP_DBS {
        for action in [Action::QueryRead, Action::SchemaRead] {
            let devs = evaluate(&devs_id, action, "worker-db", db, &cfg.permissions);
            let devops = evaluate(&devops_id, action, "worker-db", db, &cfg.permissions);
            assert!(
                matches!(devops, Decision::Allow { .. }),
                "devops must see {db} for {action:?}, got {devops:?}"
            );
            assert_eq!(devs, devops, "devs/devops drift on {db} {action:?}");
        }
    }
}

#[test]
fn devops_cannot_touch_infra_dbs() {
    // Mirror of devs_cannot_touch_infra_dbs: an accidental cto-style
    // wildcard grant on devops would leak infra DBs.
    let cfg = permissions_yml();
    let id = identity_in("devops");
    for db in INFRA_DBS {
        assert_eq!(
            evaluate(&id, Action::SchemaRead, "worker-db", db, &cfg.permissions),
            Decision::Deny,
            "devops must NOT see infra DB {db}"
        );
    }
}

#[test]
fn cto_can_query_read_every_listed_db() {
    let cfg = permissions_yml();
    let id = identity_in("cto");
    for db in APP_DBS.iter().chain(INFRA_DBS.iter()) {
        for action in [Action::QueryRead, Action::SchemaRead] {
            let decision = evaluate(&id, action, "worker-db", db, &cfg.permissions);
            assert!(
                matches!(decision, Decision::Allow { .. }),
                "cto must see {db} for {action:?}, got {decision:?}"
            );
        }
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
