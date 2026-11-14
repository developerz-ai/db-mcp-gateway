//! End-to-end test for `explain`: login via mock OIDC, call `tools/call
//! explain` with a SELECT (success), with a DELETE under a read grant
//! (`forbidden_sql`), with DML under a write grant (planned, not run), and
//! with `analyze: true` (reads only). Asserts the audit row in each case.

use crate::common;
use std::time::Duration;

use crate::common::audit::assert_audit_outcome;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use serde_json::{Value, json};

/// Same `target` server as the run_query e2e but no constraints — `explain`
/// shouldn't need a row cap and we want any timeout out of the way.
const E2E_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: engineers
    grants:
      - { server: target, database: app, action: query_read }
"#;

/// The two-tier database: reads as the provisioned read role, `query_write`
/// as `app`.
const WRITE_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - name: app
        role: dbmcp_test_ro
        password: ro-dev-only
        write_role: app
        write_password: app-dev-only

permissions:
  - group: writers
    grants:
      - { server: target, database: app, action: query_write }
"#;

async fn boot_gateway() -> LoggedInGateway {
    boot_gateway_with(E2E_YAML, "engineers").await
}

async fn boot_gateway_with(yaml: &str, group: &str) -> LoggedInGateway {
    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "explain-e2e@example.com".to_string(),
        groups: vec![group.to_string()],
    };
    spawn_logged_in(yaml, user).await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
}

async fn call_explain(url: &str, bearer: &str, sql: &str) -> Value {
    call_explain_with(url, bearer, json!({ "sql": sql })).await
}

/// `explain` on `target/app` with `extra` merged into the arguments.
async fn call_explain_with(url: &str, bearer: &str, extra: Value) -> Value {
    let mut arguments = json!({ "server": "target", "database": "app" });
    for (key, value) in extra.as_object().expect("object") {
        arguments[key] = value.clone();
    }
    client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "explain",
                "arguments": arguments
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("explain result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

#[tokio::test]
async fn explain_full_acceptance() {
    let booted = boot_gateway().await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

    // 1. Happy path: EXPLAIN of a SELECT returns a plan with a Node Type.
    let resp = call_explain(url, bearer, "SELECT 1").await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert!(
        body["plan"][0]["Plan"]["Node Type"].is_string(),
        "plan shape unexpected: {body}"
    );
    assert_audit_outcome(pool, sub, "explain", "success", "EXPLAIN SELECT 1").await;

    // 2. AST guard: EXPLAIN of a DELETE needs a `query_write` grant; under a
    //    read grant it is rejected pre-DB. Audit records the rejection.
    let resp = call_explain(url, bearer, "DELETE FROM users").await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(payload(&resp)["code"], "forbidden_sql");
    assert_audit_outcome(pool, sub, "explain", "forbidden_sql", "EXPLAIN DELETE").await;

    // 3. Forbidden when caller has no grant on the (server, database).
    let resp = client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "explain",
                "arguments": { "server": "nonexistent", "database": "app", "sql": "SELECT 1" }
            }
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(payload(&resp)["code"], "forbidden");
    assert_audit_outcome(
        pool,
        sub,
        "explain",
        "forbidden",
        "EXPLAIN forbidden server",
    )
    .await;
}

/// `analyze: true` runs a read for real timings; DML is never analyzed.
#[tokio::test]
async fn explain_analyze_runs_reads_only() {
    common::pg_target::ensure_read_role().await;
    let booted = boot_gateway_with(WRITE_YAML, "writers").await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );

    let resp = call_explain_with(url, bearer, json!({ "sql": "SELECT 1", "analyze": true })).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let plan = &payload(&resp)["plan"][0];
    assert!(plan["Plan"]["Actual Total Time"].is_number(), "{plan}");
    assert_audit_outcome(pool, sub, "explain", "success", "EXPLAIN ANALYZE SELECT").await;

    let resp = call_explain_with(
        url,
        bearer,
        json!({ "sql": "DELETE FROM pg_class_nonexistent", "analyze": true }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(payload(&resp)["code"], "forbidden_sql");
    assert_audit_outcome(
        pool,
        sub,
        "explain",
        "forbidden_sql",
        "EXPLAIN ANALYZE DELETE",
    )
    .await;
}

/// Under `query_write`, plain EXPLAIN of DML returns the plan and changes
/// nothing.
#[tokio::test]
async fn explain_plans_dml_under_a_write_grant() {
    common::pg_target::ensure_read_role().await;
    let booted = boot_gateway_with(WRITE_YAML, "writers").await;
    let (url, bearer, pool, sub) = (
        booted.url.as_str(),
        booted.bearer.as_str(),
        &booted.state_db,
        booted.user_sub.as_str(),
    );
    let target = sqlx::PgPool::connect("postgres://app:app-dev-only@localhost:5434/app")
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let table = format!("explain_dml_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE TABLE \"{table}\" (id bigint PRIMARY KEY)"))
        .execute(&target)
        .await
        .expect("create scratch table");
    sqlx::query(&format!("INSERT INTO \"{table}\" VALUES (1)"))
        .execute(&target)
        .await
        .expect("seed scratch row");

    let sql = format!("DELETE FROM \"{table}\" WHERE id = 1");
    let resp = call_explain(url, bearer, &sql).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    assert!(payload(&resp)["plan"][0]["Plan"]["Node Type"].is_string());
    assert_audit_outcome(
        pool,
        sub,
        "explain",
        "success",
        "EXPLAIN DELETE under write",
    )
    .await;

    let left: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"{table}\""))
        .fetch_one(&target)
        .await
        .unwrap();
    assert_eq!(left, 1, "plain EXPLAIN must not execute the DELETE");
    sqlx::query(&format!("DROP TABLE \"{table}\""))
        .execute(&target)
        .await
        .expect("drop scratch table");
}
