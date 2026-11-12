//! End-to-end test for `explain`: login via mock OIDC, call `tools/call
//! explain` with a SELECT (success) and with a DELETE (must be rejected by
//! the AST guard with `forbidden_sql`). Asserts audit row exists with the
//! correct outcome in each case.

mod common;

use std::time::Duration;

use common::audit::assert_audit_outcome;
use common::gateway::{LoggedInGateway, spawn_logged_in};
use common::idp::MockUser;
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

async fn boot_gateway() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "explain-e2e@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(E2E_YAML, user).await
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
}

async fn call_explain(url: &str, bearer: &str, sql: &str) -> Value {
    client()
        .post(format!("{url}/mcp"))
        .bearer_auth(bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "explain",
                "arguments": { "server": "target", "database": "app", "sql": sql }
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

    // 2. AST guard: EXPLAIN of a DELETE must be rejected pre-DB. Even
    //    though Postgres' EXPLAIN-without-ANALYZE doesn't execute, we stay
    //    conservative — see `exec::sql_guard`. Audit records the rejection.
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
