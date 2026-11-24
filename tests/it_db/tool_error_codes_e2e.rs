//! Stable error codes over real MCP calls against the live target, each with
//! its audit row (spec 03 §Errors): `syntax_error`, `permission_denied` and
//! `unavailable`. `undefined_object` is `tool_errors_body_e2e`'s,
//! `rate_limited` (+ `Retry-After`) `it_offline::transport_overload`'s, and
//! `internal` `audit_dispatch_panic_real_db`'s — no request reaches it.

use serde_json::json;

use crate::agent_walk_support::{Agent, Fixture};
use crate::common::pg_target::{READ_ROLE, READ_ROLE_PASSWORD, ensure_read_role};

/// `target/app` as the read-only role (SELECT on `public` only), and `down`:
/// a server nothing listens on.
fn yaml() -> String {
    format!(
        r#"
servers:
  - name: target
    kind: postgres
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - name: app
        role: {READ_ROLE}
        password: {READ_ROLE_PASSWORD}
  - name: down
    kind: postgres
    host: 127.0.0.1
    port: 1
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: engineers
    grants:
      - {{ server: target, database: app, action: query_read }}
      - {{ server: down, database: app, action: query_read }}
"#
    )
}

/// The gateway's parser accepts it; Postgres rejects it at execution
/// (`invalid_text_representation`). Any statement-level refusal that is not
/// a privilege or a missing name is `syntax_error` — SQL the agent must fix.
/// (SQL the gateway itself cannot parse is `forbidden_sql`, before dispatch.)
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_statement_postgres_rejects_is_syntax_error() {
    ensure_read_role().await;
    let agent = Agent::boot_with(&yaml()).await;
    let args = json!({"server": "target", "database": "app", "sql": "SELECT 'not a number'::int"});
    let called = agent.call("run_query", args).await;

    assert!(called.is_error(), "{:?}", called.response);
    assert_eq!(called.payload["code"], "syntax_error", "{}", called.payload);
    assert_eq!(called.payload["request_id"], called.request_id.as_str());
    agent.assert_audited(&called, "syntax_error").await;
}

/// The read role has no USAGE on a schema the owner just created: Postgres
/// answers SQLSTATE 42501, which reaches the agent as `permission_denied`
/// with the role name withheld.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_table_the_role_may_not_read_is_permission_denied() {
    ensure_read_role().await;
    let fixture = Fixture::create(1).await;
    let agent = Agent::boot_with(&yaml()).await;
    let sql = format!("SELECT * FROM \"{}\".items", fixture.schema);
    let args = json!({"server": "target", "database": "app", "sql": sql});
    let called = agent.call("run_query", args).await;
    fixture.drop_schema().await;

    assert!(called.is_error(), "{:?}", called.response);
    let body = &called.payload;
    assert_eq!(body["code"], "permission_denied", "{body}");
    assert!(!body.to_string().contains(READ_ROLE), "role leaked: {body}");
    let (outcome, message) = agent.audit_of(&called).await;
    assert_eq!(outcome, "permission_denied");
    assert!(
        !message.unwrap_or_default().contains(READ_ROLE),
        "role leaked into the audit row"
    );
}

/// A target that refuses the connection is `unavailable` — retryable, and
/// with no host, port or role in what the agent sees.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_target_that_refuses_connections_is_unavailable() {
    let agent = Agent::boot_with(&yaml()).await;
    let args = json!({"server": "down", "database": "app", "sql": "SELECT 1"});
    let called = agent.call("run_query", args).await;

    assert!(called.is_error(), "{:?}", called.response);
    let body = &called.payload;
    assert_eq!(body["code"], "unavailable", "{body}");
    let rendered = body.to_string();
    for secret in ["127.0.0.1", "app-dev-only", "password"] {
        assert!(!rendered.contains(secret), "{secret} leaked: {body}");
    }
    agent.assert_audited(&called, "unavailable").await;
}
