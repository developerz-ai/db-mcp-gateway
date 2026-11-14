//! The read and write tiers of one database (plan 101 slice 12 steps 1, 4):
//! a write-tier caller's reads run as the read `role`, its writes as
//! `write_role`; a write reports `rows_affected` in the response and the audit
//! row; `dry_run` executes, reports and rolls back, audited `dry_run`.
//!
//! Needs the target Postgres (`bin/dev up` → :5434).

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::{READ_ROLE, TARGET_USER, ensure_read_role};
use serde_json::{Value, json};

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
  - group: readers
    grants:
      - { server: target, database: app, action: query_read }
"#;

/// A logged-in caller in `group`, plus a scratch table holding row `id = 1`.
struct Fixture {
    gw: LoggedInGateway,
    target: sqlx::PgPool,
    table: String,
}

impl Fixture {
    async fn new(group: &str) -> Self {
        ensure_read_role().await;
        let user = MockUser {
            sub: format!("tier-{}", uuid::Uuid::new_v4().simple()),
            email: "tier-e2e@example.com".into(),
            groups: vec![group.into()],
        };
        let gw = spawn_logged_in(WRITE_YAML, user).await;
        let target = sqlx::PgPool::connect("postgres://app:app-dev-only@localhost:5434/app")
            .await
            .expect("target-db reachable; run `bin/dev up`");
        let table = format!("tier_e2e_{}", uuid::Uuid::new_v4().simple());
        for sql in [
            format!("CREATE TABLE \"{table}\" (id bigint PRIMARY KEY, note text)"),
            format!("INSERT INTO \"{table}\" VALUES (1, 'one'), (2, 'two')"),
        ] {
            sqlx::query(&sql)
                .execute(&target)
                .await
                .expect("scratch table");
        }
        Self { gw, target, table }
    }

    async fn run(&self, args: Value) -> Value {
        let mut arguments = json!({ "server": "target", "database": "app" });
        for (key, value) in args.as_object().expect("object") {
            arguments[key] = value.clone();
        }
        reqwest::Client::new()
            .post(format!("{}/mcp", self.gw.url))
            .bearer_auth(&self.gw.bearer)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "run_query", "arguments": arguments }
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn note(&self, id: i64) -> String {
        sqlx::query_scalar(&format!(
            "SELECT note FROM \"{}\" WHERE id = $1",
            self.table
        ))
        .bind(id)
        .fetch_one(&self.target)
        .await
        .unwrap()
    }

    async fn latest(&self, label: &str) -> db_mcp_gateway::audit::AuditRow {
        latest_audit(&self.gw.state_db, &self.gw.user_sub, "run_query", label).await
    }

    async fn drop_table(self) {
        sqlx::query(&format!("DROP TABLE \"{}\"", self.table))
            .execute(&self.target)
            .await
            .expect("drop scratch table");
    }
}

fn payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text content: {response}"));
    serde_json::from_str(text).expect("payload is valid JSON")
}

#[tokio::test]
async fn reads_run_as_role_and_writes_as_write_role() {
    let fx = Fixture::new("writers").await;

    let resp = fx.run(json!({ "sql": "SELECT current_user::text" })).await;
    assert_eq!(payload(&resp)["rows"][0][0], READ_ROLE, "{resp}");
    assert_eq!(fx.latest("tier read").await.rows_affected, None);

    let sql = format!(
        "UPDATE \"{}\" SET note = current_user WHERE id = 1 RETURNING note",
        fx.table
    );
    let resp = fx.run(json!({ "sql": sql })).await;
    let body = payload(&resp);
    assert_eq!(body["rows"][0][0], TARGET_USER, "{resp}");
    assert_eq!(body["rows_affected"], 1);
    let row = fx.latest("tier write").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.rows_affected, Some(1));
    assert_eq!(fx.note(1).await, TARGET_USER, "the write committed");
    fx.drop_table().await;
}

#[tokio::test]
async fn dry_run_reports_rows_affected_and_rolls_back() {
    let fx = Fixture::new("writers").await;

    let sql = format!("UPDATE \"{}\" SET note = 'changed'", fx.table);
    let resp = fx.run(json!({ "sql": sql, "dry_run": true })).await;
    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["rows_affected"], 2);
    assert_eq!(body["dry_run"], true);

    let row = fx.latest("dry run").await;
    assert_eq!(row.outcome, "dry_run");
    assert_eq!(row.rows_affected, Some(2));
    assert_eq!(fx.note(1).await, "one", "dry_run must leave no change");

    // `dry_run` on a read is meaningless: refused, audited.
    let resp = fx.run(json!({ "sql": "SELECT 1", "dry_run": true })).await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    assert_eq!(fx.latest("dry run read").await.outcome, "invalid_arguments");
    fx.drop_table().await;
}

#[tokio::test]
async fn read_tier_cannot_dry_run_a_write() {
    let fx = Fixture::new("readers").await;

    let sql = format!("DELETE FROM \"{}\"", fx.table);
    let resp = fx.run(json!({ "sql": sql, "dry_run": true })).await;
    assert_eq!(payload(&resp)["code"], "forbidden_sql", "{resp}");
    assert_eq!(
        fx.latest("read-tier dry run").await.outcome,
        "forbidden_sql"
    );
    assert_eq!(fx.note(1).await, "one");
    fx.drop_table().await;
}
