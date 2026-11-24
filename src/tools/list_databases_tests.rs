use super::*;
use crate::auth::SessionId;
use crate::exec::DEFAULT_STATEMENT_TIMEOUT_MS;
use crate::tools::audit_dispatch::Reply;
use crate::tools::{GATEWAY_ROW_LIMIT_CEILING, RUN_QUERY};

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
      - { name: billing, role: ro, password: billing_pw }
      - { name: analytics, role: ro, password: analytics_pw }
      - name: sandbox
        role: sandbox_ro
        password: sandbox_pw
        write_role: sandbox_rw
        write_password: sandbox_rw_pw
  - name: cache
    kind: redis
    description: Cache
    host: cache.internal
    databases:
      - { name: "0", role: ro, password: cache_pw }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: app, action: schema_read }
  - group: analytics-team
    grants:
      - server: prod
        database: analytics
        action: query_read
        constraints: { row_limit: 500, statement_timeout_ms: 5000, require_reason: true }
  - group: ops
    grants:
      - { server: prod, database: "*", action: schema_read }
  - group: writers
    grants:
      - { server: prod, database: sandbox, action: query_write }
      - { server: prod, database: sandbox, action: history_read }
  - group: historians
    grants:
      - { server: prod, database: billing, action: history_read }
  - group: cachers
    grants:
      - { server: cache, database: "*", action: query_read }
"#;

fn load() -> ConfigFile {
    ConfigFile::from_yaml_str(YAML).expect("yaml parses")
}

fn compute_for(groups: &[&str], server: Option<&str>) -> Outcome {
    let args = Arguments {
        server: server.map(str::to_string),
    };
    compute_outcome(Value::from(1), &identity(groups), &load(), &[], &args)
}

fn payload(outcome: &Outcome) -> Value {
    let Reply::Response(response) = &outcome.reply else {
        panic!("expected a rendered response, got {:?}", outcome.reply);
    };
    let value = serde_json::to_value(response).unwrap();
    let text = value["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

fn names(outcome: &Outcome) -> Vec<String> {
    payload(outcome)["databases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            format!(
                "{}/{}",
                d["server"].as_str().unwrap(),
                d["name"].as_str().unwrap()
            )
        })
        .collect()
}

#[test]
fn engineer_sees_only_app() {
    let outcome = compute_for(&["engineers"], Some("prod"));
    assert_eq!(outcome.code, OutcomeCode::Success);
    assert_eq!(names(&outcome), vec!["prod/app"]);
}

#[test]
fn ops_with_wildcard_sees_all_of_prod() {
    let outcome = compute_for(&["ops"], Some("prod"));
    assert_eq!(
        names(&outcome),
        vec!["prod/app", "prod/billing", "prod/analytics", "prod/sandbox"]
    );
}

/// No grant on the named server → `forbidden`, never an empty list.
#[test]
fn user_with_no_grants_gets_forbidden_not_empty() {
    let outcome = compute_for(&["finance"], Some("prod"));
    assert_eq!(outcome.code, OutcomeCode::Forbidden);
    assert!(matches!(outcome.reply, Reply::ToolError));
}

/// A `history_read`-only database does not make `list_databases` answer.
#[test]
fn history_only_database_is_not_listed() {
    let outcome = compute_for(&["historians"], Some("prod"));
    assert_eq!(outcome.code, OutcomeCode::Forbidden);
}

/// Unknown server → same `forbidden`, same message: names cannot be probed.
#[test]
fn unknown_server_is_forbidden_with_same_message() {
    let unknown = compute_for(&["engineers"], Some("nonexistent"));
    let denied = compute_for(&["finance"], Some("prod"));
    assert_eq!(unknown.code, OutcomeCode::Forbidden);
    assert_eq!(unknown.error_message, denied.error_message);
    assert_eq!(
        unknown.error_message.as_deref(),
        Some("no grants for this server")
    );
}

/// M9: no `server` lists every visible database across servers.
#[test]
fn omitted_server_lists_every_visible_server() {
    let outcome = compute_for(&["engineers", "cachers"], None);
    assert_eq!(outcome.code, OutcomeCode::Success);
    assert_eq!(names(&outcome), vec!["prod/app", "cache/0"]);
    assert_eq!(outcome.row_count, Some(2));
}

/// Without `server` nothing was probed, so no grants is an empty list.
#[test]
fn omitted_server_with_no_grants_is_empty() {
    let outcome = compute_for(&["finance"], None);
    assert_eq!(outcome.code, OutcomeCode::Success);
    assert!(names(&outcome).is_empty());
}

/// M10: the grant's caps are reported as the tools enforce them.
#[test]
fn reports_effective_limits_per_action() {
    let body = payload(&compute_for(&["analytics-team"], Some("prod")));
    let db = &body["databases"][0];
    assert_eq!(db["kind"], "postgres");
    assert_eq!(
        db["actions"],
        serde_json::json!(["schema_read", "query_read"])
    );
    assert_eq!(db["writes"], false);
    let query = &db["limits"][1];
    assert_eq!(query["action"], "query_read");
    assert_eq!(query["row_limit"], 500);
    assert_eq!(query["statement_timeout_ms"], 5000);
    assert_eq!(query["require_reason"], true);
    assert_eq!(
        query["tools"],
        serde_json::json!(["run_query", "sample_table", "explain", "cancel_query"])
    );
}

/// A grant without caps reports the gateway ceilings, never "unbounded".
#[test]
fn silent_grant_reports_gateway_ceilings() {
    let body = payload(&compute_for(&["writers"], Some("prod")));
    let db = &body["databases"][0];
    assert_eq!(db["name"], "sandbox");
    assert_eq!(db["writes"], true);
    assert_eq!(
        db["actions"],
        serde_json::json!(["schema_read", "query_read", "query_write", "history_read"])
    );
    let limits = db["limits"].as_array().unwrap();
    assert_eq!(
        limits.len(),
        3,
        "query_write has no limits entry: {limits:?}"
    );
    assert_eq!(limits[1]["row_limit"], GATEWAY_ROW_LIMIT_CEILING);
    assert_eq!(
        limits[1]["statement_timeout_ms"],
        DEFAULT_STATEMENT_TIMEOUT_MS
    );
    assert_eq!(limits[2]["action"], "history_read");
    assert!(limits[2].get("statement_timeout_ms").is_none());
    assert!(limits[0].get("row_limit").is_none());
}

/// `query_write` on a database without `write_role` is not `writes`
/// (boot refuses it anyway; the view never claims a write it cannot do).
#[test]
fn query_write_without_write_role_is_not_writes() {
    let mut config = load();
    config.permissions[3].grants[0].database = "app".into();
    let server = &config.servers[0];
    let view = database_view(
        &identity(&["writers"]),
        &config,
        &[],
        server,
        &server.databases[0],
    )
    .expect("held");
    assert!(view.actions.contains(&"query_write"));
    assert!(!view.writes);
}

/// Tools are filtered by engine: Redis offers `run_query` only.
#[test]
fn redis_offers_run_query_only() {
    let body = payload(&compute_for(&["cachers"], Some("cache")));
    let db = &body["databases"][0];
    assert_eq!(db["kind"], "redis");
    assert_eq!(db["tools"], serde_json::json!([RUN_QUERY]));
}

/// No credential, role or host ever reaches the wire.
#[test]
fn no_credential_in_output() {
    for groups in [
        vec!["engineers"],
        vec!["analytics-team"],
        vec!["ops", "writers", "cachers"],
    ] {
        let body = payload(&compute_for(&groups, None)).to_string();
        for secret in [
            "hunter2",
            "billing_pw",
            "analytics_pw",
            "sandbox_pw",
            "sandbox_rw",
            "cache_pw",
        ] {
            assert!(!body.contains(secret), "leak {secret}: {body}");
        }
        assert!(!body.contains("password"), "field leak: {body}");
        assert!(!body.contains("role"), "field leak: {body}");
        assert!(!body.contains("host"), "field leak: {body}");
    }
}
