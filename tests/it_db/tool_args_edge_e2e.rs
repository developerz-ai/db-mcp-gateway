//! The `tools/call` argument edge: a NUL, a control character, an oversized
//! value or an unknown key is `invalid_arguments` before any intent row or
//! target call — audited, with the refused value written nowhere.
//!
//! Needs the target Postgres (`bin/dev up` → :5434) and the state DB.

use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::ensure_read_role;
use serde_json::{Value, json};

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
  - name: analytics
    kind: mongo
    description: never reached
    host: analytics.example.invalid
    databases:
      - { name: dw, role: ro, password: dwpw }

permissions:
  - group: writers
    grants:
      - { server: target, database: app, action: query_write }
      - { server: analytics, database: dw, action: query_read }
"#;

struct Fixture {
    gw: LoggedInGateway,
    target: sqlx::PgPool,
    table: String,
}

impl Fixture {
    async fn new() -> Self {
        ensure_read_role().await;
        let user = MockUser {
            sub: format!("args-edge-{}", uuid::Uuid::new_v4().simple()),
            email: "args-edge@example.com".into(),
            groups: vec!["writers".into()],
        };
        let gw = spawn_logged_in(YAML, user).await;
        let target = sqlx::PgPool::connect("postgres://app:app-dev-only@localhost:5434/app")
            .await
            .expect("target-db reachable; run `bin/dev up`");
        let table = format!("args_edge_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE TABLE \"{table}\" (v text)"))
            .execute(&target)
            .await
            .expect("scratch table");
        Self { gw, target, table }
    }

    async fn call(&self, tool: &str, arguments: Value) -> Value {
        reqwest::Client::new()
            .post(format!("{}/mcp", self.gw.url))
            .bearer_auth(&self.gw.bearer)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn rows(&self) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM \"{}\"", self.table))
            .fetch_one(&self.target)
            .await
            .unwrap()
    }

    async fn intents(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_call_intents WHERE user_sub = $1")
            .bind(&self.gw.user_sub)
            .fetch_one(&self.gw.state_db)
            .await
            .unwrap()
    }

    async fn latest(&self, tool: &str, label: &str) -> db_mcp_gateway::audit::AuditRow {
        latest_audit(&self.gw.state_db, &self.gw.user_sub, tool, label).await
    }

    async fn finish(self) {
        sqlx::query(&format!("DROP TABLE \"{}\"", self.table))
            .execute(&self.target)
            .await
            .expect("drop scratch table");
        delete_audit_calls(&self.gw.state_db, &self.gw.user_sub).await;
    }
}

fn assert_invalid_params(response: &Value) -> String {
    assert_eq!(response["error"]["code"], -32602, "{response}");
    response["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn tool_error_code(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text content: {response}"));
    serde_json::from_str::<Value>(text).unwrap()["code"].clone()
}

/// The live-run finding: a NUL in `reason` used to let the write commit and
/// then fail every audit write. Now nothing reaches the target and the
/// refusal is audited.
#[tokio::test]
#[serial_test::parallel(world)]
async fn nul_in_reason_never_reaches_the_target_and_is_audited() {
    let f = Fixture::new().await;
    let sql = format!("INSERT INTO \"{}\" (v) VALUES ('nul-test')", f.table);
    let resp = f
        .call(
            "run_query",
            json!({ "server": "target", "database": "app", "sql": sql, "reason": "ticket\u{0}123" }),
        )
        .await;
    let message = assert_invalid_params(&resp);
    assert!(message.contains("`reason`"), "{message}");

    assert_eq!(f.rows().await, 0, "the write must not run");
    assert_eq!(
        f.intents().await,
        0,
        "no intent: the target was never in play"
    );
    let row = f.latest("run_query", "nul reason").await;
    assert_eq!(row.outcome, "invalid_arguments");
    assert_eq!(row.server, None);
    assert_eq!(row.reason, None);
    f.finish().await;
}

/// An oversized identifier or reason is refused at the edge and audited
/// untargeted, instead of failing the audit insert (index row too large).
#[tokio::test]
#[serial_test::parallel(world)]
async fn oversized_values_are_refused_and_audited() {
    let f = Fixture::new().await;
    let cases = [
        (
            "server",
            json!({ "server": "s".repeat(500_000), "database": "app", "sql": "select 1" }),
        ),
        (
            "reason",
            json!({ "server": "target", "database": "app", "sql": "select 1", "reason": "r".repeat(200_000) }),
        ),
        (
            "database",
            json!({ "server": "target", "database": "bad\u{1b}[2J", "sql": "select 1" }),
        ),
    ];
    for (field, arguments) in cases {
        let resp = f.call("run_query", arguments).await;
        let message = assert_invalid_params(&resp);
        assert!(message.contains(&format!("`{field}`")), "{message}");
        assert!(message.len() < 100, "value not echoed: {}", message.len());
        let row = f.latest("run_query", field).await;
        assert_eq!(row.outcome, "invalid_arguments", "{field}");
        assert_eq!(row.server, None, "{field}");
    }
    f.finish().await;
}

/// spec 03: an unknown key is `invalid_arguments`, and a mistyped field is
/// named in the message.
#[tokio::test]
#[serial_test::parallel(world)]
async fn unknown_keys_and_mistyped_fields_are_named() {
    let f = Fixture::new().await;
    for tool in ["run_query", "explain", "sample_table", "describe_schema"] {
        let resp = f
            .call(
                tool,
                json!({ "server": "target", "database": "app", "sql": "select 1",
                        "table": "t", "bogus": 1 }),
            )
            .await;
        let message = assert_invalid_params(&resp);
        assert!(
            message.contains("bogus") || message.contains("unknown field"),
            "{tool}: {message}"
        );
        let row = f.latest(tool, "unknown key").await;
        assert_eq!(row.outcome, "invalid_arguments", "{tool}");
    }

    let resp = f
        .call(
            "run_query",
            json!({ "server": "target", "database": "app", "sql": "select 1", "limit": -1 }),
        )
        .await;
    let message = assert_invalid_params(&resp);
    assert!(message.contains("-1"), "{message}");
    f.finish().await;
}

/// `explain` on Mongo has no SQL to parse: a stable `unsupported_backend`,
/// answered before the parser and before any target call.
#[tokio::test]
#[serial_test::parallel(world)]
async fn explain_on_mongo_is_unsupported_backend() {
    let f = Fixture::new().await;
    let resp = f
        .call(
            "explain",
            json!({ "server": "analytics", "database": "dw", "sql": "db.events.find()" }),
        )
        .await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(tool_error_code(&resp), "unsupported_backend", "{resp}");
    let row = f.latest("explain", "mongo explain").await;
    assert_eq!(row.outcome, "unsupported_backend");
    assert_eq!(f.intents().await, 0);
    f.finish().await;
}
