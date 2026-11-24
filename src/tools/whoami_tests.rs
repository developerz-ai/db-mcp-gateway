use super::*;
use crate::auth::SessionId;
use crate::tools::audit_dispatch::Reply;

const YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: Prod
    host: prod.db.internal
    databases:
      - { name: app, role: ro, password: hunter2 }
      - { name: billing, role: ro, password: billing_pw }

permissions:
  - group: engineers
    grants:
      - server: prod
        database: app
        action: query_read
        constraints: { row_limit: 50 }
      - { server: prod, database: billing, action: history_read }
  - group: svc-ci
    grants:
      - { server: prod, database: billing, action: schema_read }
"#;

fn identity(kind: IdentityKind, sub: &str, groups: &[&str]) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: sub.to_string(),
        user_email: format!("{sub}@example.com"),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        issued_at: Utc::now(),
        kind,
    }
}

fn payload(identity: &Identity, expires_at: Option<DateTime<Utc>>) -> Value {
    let config = ConfigFile::from_yaml_str(YAML).expect("yaml parses");
    let outcome = compute_outcome(
        Value::from(1),
        identity,
        &config,
        &[],
        expires_at,
        Instant::now(),
    );
    assert_eq!(outcome.code, OutcomeCode::Success);
    let Reply::Response(response) = &outcome.reply else {
        panic!("expected a rendered response, got {:?}", outcome.reply);
    };
    let value = serde_json::to_value(response).unwrap();
    serde_json::from_str(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[test]
fn sso_caller_sees_identity_expiry_and_own_grants() {
    let expires = Utc::now();
    let body = payload(
        &identity(IdentityKind::Sso, "alice", &["engineers"]),
        Some(expires),
    );
    assert_eq!(body["sub"], "alice");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["auth"], "sso");
    assert!(body.get("service_account").is_none());
    assert_eq!(body["groups"], serde_json::json!(["engineers"]));
    assert_eq!(
        body["session_expires_at"],
        serde_json::to_value(expires).unwrap()
    );
    let grants = body["grants"].as_array().unwrap();
    assert_eq!(
        grants.len(),
        2,
        "history-only billing is a grant too: {grants:?}"
    );
    assert_eq!(grants[0]["name"], "app");
    assert_eq!(grants[0]["limits"][1]["row_limit"], 50);
    assert_eq!(grants[1]["actions"], serde_json::json!(["history_read"]));
}

#[test]
fn service_account_is_named_and_has_no_session() {
    let body = payload(
        &identity(IdentityKind::Service, "service:ci-bot", &["svc-ci"]),
        None,
    );
    assert_eq!(body["auth"], "service");
    assert_eq!(body["service_account"], "ci-bot");
    assert!(body.get("session_expires_at").is_none());
    let grants = body["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["name"], "billing");
}

#[test]
fn no_group_means_no_grants_and_no_credentials() {
    let body = payload(&identity(IdentityKind::Sso, "bob", &[]), None);
    assert_eq!(body["grants"], serde_json::json!([]));
    let text = body.to_string();
    assert!(
        !text.contains("hunter2") && !text.contains("billing_pw"),
        "{text}"
    );
}
