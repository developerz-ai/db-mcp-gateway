use super::*;
use crate::auth::SessionId;
use crate::config::ConfigFile;

fn identity(groups: &[&str]) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: "u".to_string(),
        user_email: "u@example.com".to_string(),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        issued_at: chrono::Utc::now(),
        kind: crate::auth::IdentityKind::Sso,
    }
}

const YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: Customer-facing prod
    host: prod.db.internal
    databases:
      - { name: app, role: ro, password: hunter2 }
  - name: staging
    kind: postgres
    description: Staging
    host: staging.db.internal
    databases:
      - { name: app, role: ro, password: stagingpw }
  - name: analytics
    kind: mongo
    description: Analytics
    host: an.db.internal
    databases:
      - { name: warehouse, role: ro, password: dwpw }

permissions:
  - group: backend-engineers
    grants:
      - { server: staging, database: "*", action: query_read }
      - { server: prod,    database: "*", action: schema_read }
  - group: analytics-team
    grants:
      - { server: analytics, database: "*", action: query_read }
"#;

fn load() -> ConfigFile {
    ConfigFile::from_yaml_str(YAML).expect("yaml parses")
}

/// Drives the sync `compute_outcome` directly. Unit-testing the filter +
/// shape logic doesn't need the audit chokepoint (covered by integration
/// tests against a real state DB).
fn body_for(groups: &[&str]) -> String {
    let outcome = compute_outcome(Value::from(1), &identity(groups), &load(), &[]);
    let crate::tools::audit_dispatch::Reply::Response(response) = &outcome.reply else {
        panic!("expected a rendered response, got {:?}", outcome.reply);
    };
    let json = serde_json::to_value(response).unwrap();
    json["result"]["content"][0]["text"]
        .as_str()
        .expect("content[0].text is the JSON-stringified payload")
        .to_string()
}

#[test]
fn engineer_sees_prod_and_staging_but_not_analytics() {
    let body = body_for(&["backend-engineers"]);
    assert!(body.contains("\"name\":\"prod\""), "{body}");
    assert!(body.contains("\"name\":\"staging\""), "{body}");
    assert!(!body.contains("\"name\":\"analytics\""), "{body}");
}

#[test]
fn analyst_only_sees_analytics() {
    let body = body_for(&["analytics-team"]);
    assert!(body.contains("\"name\":\"analytics\""), "{body}");
    assert!(!body.contains("\"name\":\"prod\""), "{body}");
    assert!(!body.contains("\"name\":\"staging\""), "{body}");
}

#[test]
fn user_in_no_group_sees_nothing() {
    let body = body_for(&[]);
    assert!(body.contains("\"servers\":[]"), "{body}");
}

/// row_count in Outcome equals the visible server count — operators
/// reading audit_calls.row_count get the same answer.
#[test]
fn row_count_matches_visible_servers() {
    let outcome = compute_outcome(
        Value::from(1),
        &identity(&["backend-engineers"]),
        &load(),
        &[],
    );
    assert_eq!(outcome.code, OutcomeCode::Success);
    assert_eq!(outcome.row_count, Some(2));
    assert_eq!(outcome.truncated, Some(false));
}

/// The hard one: no inline password value (literal, env-ref, or vault-ref)
/// can ever appear in the tool output. Hunter2 is in the YAML; it must
/// never reach the wire.
#[test]
fn no_password_ever_appears_in_output() {
    for groups in [
        vec!["backend-engineers"],
        vec!["analytics-team"],
        vec!["backend-engineers", "analytics-team"],
    ] {
        let body = body_for(&groups);
        assert!(!body.contains("hunter2"), "leaked literal password: {body}");
        assert!(
            !body.contains("stagingpw"),
            "leaked literal password: {body}"
        );
        assert!(!body.contains("dwpw"), "leaked literal password: {body}");
        assert!(!body.contains("password"), "field name leaked: {body}");
        assert!(!body.contains("role"), "role name leaked: {body}");
        assert!(!body.contains("host"), "host leaked: {body}");
    }
}

/// M9: each server inlines the databases `list_databases` would list, with
/// the same per-database view.
#[test]
fn servers_inline_their_visible_databases() {
    let body: Value = serde_json::from_str(&body_for(&["backend-engineers"])).unwrap();
    let servers = body["servers"].as_array().unwrap();
    let prod = servers.iter().find(|s| s["name"] == "prod").unwrap();
    let app = &prod["databases"][0];
    assert_eq!(app["name"], "app");
    assert_eq!(app["actions"], serde_json::json!(["schema_read"]));
    let staging = servers.iter().find(|s| s["name"] == "staging").unwrap();
    assert_eq!(
        staging["databases"][0]["actions"],
        serde_json::json!(["schema_read", "query_read"])
    );
}
