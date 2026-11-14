//! A `run_query` write through the gateway commits an intent row carrying
//! the call's `sql` and `reason` — the same values its completion row records
//! — so an `abandoned` row for it would still say what ran.
//!
//! Needs the target Postgres (`bin/dev up` → :5434) and the state DB.

mod common;

use common::audit::latest_audit;
use common::cleanup::delete_audit_calls;
use common::gateway::spawn_logged_in;
use common::idp::MockUser;
use common::pg_target::ensure_read_role;
use serde_json::json;

const YAML: &str = r#"
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

#[tokio::test]
async fn write_intent_records_the_calls_sql_and_reason() {
    ensure_read_role().await;
    let user = MockUser {
        sub: format!("intent-e2e-{}", uuid::Uuid::new_v4().simple()),
        email: "intent-e2e@example.com".into(),
        groups: vec!["writers".into()],
    };
    let gw = spawn_logged_in(YAML, user).await;
    let target = sqlx::PgPool::connect("postgres://app:app-dev-only@localhost:5434/app")
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let table = format!("intent_e2e_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE TABLE \"{table}\" (v text)"))
        .execute(&target)
        .await
        .expect("scratch table");

    let sql = format!("INSERT INTO \"{table}\" (v) VALUES ('intent')");
    let reason = "OPS-11 intent attribution";
    let resp: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(&gw.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "run_query", "arguments": {
                "server": "target", "database": "app", "sql": sql, "reason": reason
            } }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["result"]["isError"], false, "{resp}");

    let row = latest_audit(&gw.state_db, &gw.user_sub, "run_query", "write").await;
    assert_eq!(row.outcome, "success");
    let (access, intent_sql, intent_reason): (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT access, sql, reason FROM audit_call_intents WHERE request_id = $1")
            .bind(&row.request_id)
            .fetch_one(&gw.state_db)
            .await
            .expect("the write committed an intent row");
    assert_eq!(access, "write");
    assert_eq!(intent_sql.as_deref(), Some(sql.as_str()));
    assert_eq!(intent_reason.as_deref(), Some(reason));
    assert_eq!(intent_sql, row.sql, "intent and completion agree on sql");
    assert_eq!(
        intent_reason, row.reason,
        "intent and completion agree on reason"
    );

    sqlx::query(&format!("DROP TABLE \"{table}\""))
        .execute(&target)
        .await
        .expect("drop scratch table");
    delete_audit_calls(&gw.state_db, &gw.user_sub).await;
}
