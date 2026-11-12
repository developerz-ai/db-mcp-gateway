//! Authz regression E2E for `sample_table` — the tool returns *row data*, so
//! it must be gated exactly like `run_query`:
//!
//!   1. a `schema_read`-only grant is metadata-only → `forbidden` (this used
//!      to succeed: `sample_table` evaluated `Action::SchemaRead`, which a
//!      bare `schema_read` grant satisfies, leaking table contents),
//!   2. a `query_read` grant samples rows,
//!   3. `constraints.require_reason` blocks a sample without a reason and the
//!      audit row carries the reason when one is supplied.
//!
//! Real Postgres throughout (`bin/dev up` → state DB :5435, target DB :5434).

mod common;

use std::time::Duration;

use common::gateway::{LoggedInGateway, spawn_logged_in};
use common::idp::MockUser;
use common::pg_target;
use db_mcp_gateway::audit::AuditRow;
use db_mcp_gateway::exec::{DbAdapter, ExecQuery, PgAdapter};
use serde_json::{Value, json};

const TOOL: &str = "sample_table";

/// One config, three groups: metadata-only, ordinary reader, and a reader
/// whose grant demands a reason. Each test logs in as a user in exactly one
/// of them.
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
        description: Local target-db

permissions:
  - group: metadata-only
    grants:
      - { server: target, database: app, action: schema_read }
  - group: engineers
    grants:
      - { server: target, database: app, action: query_read }
  - group: reason-required
    grants:
      - server: target
        database: app
        action: query_read
        constraints:
          require_reason: true
"#;

async fn boot_gateway(group: &str) -> LoggedInGateway {
    let user = MockUser {
        sub: format!("test-user-{}", uuid::Uuid::new_v4().simple()),
        email: "sample-authz-e2e@example.com".to_string(),
        groups: vec![group.to_string()],
    };
    spawn_logged_in(E2E_YAML, user).await
}

async fn call_sample_table(booted: &LoggedInGateway, mut args: Value) -> Value {
    args["server"] = json!("target");
    args["database"] = json!("app");
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", booted.url))
        .bearer_auth(&booted.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": TOOL, "arguments": args }
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
        .expect("sample_table result is JSON-stringified text content");
    serde_json::from_str(text).expect("payload is valid JSON")
}

/// The audit row is non-negotiable on every dispatch — fetch the caller's
/// latest `sample_table` row and return it for outcome/reason assertions.
async fn latest_audit(booted: &LoggedInGateway, label: &str) -> AuditRow {
    common::audit::latest_audit(&booted.state_db, &booted.user_sub, TOOL, label).await
}

/// A real table with real rows in a throwaway schema — never a mock: the
/// point is that `sample_table` either does or does not hand these rows back.
struct Fixture {
    adapter: PgAdapter,
    schema: String,
}

impl Fixture {
    async fn create() -> Self {
        let adapter = pg_target::adapter().await;
        let schema = format!("sampleauthz_{}", uuid::Uuid::new_v4().simple());
        let fixture = Self { adapter, schema };
        fixture
            .exec(&format!("CREATE SCHEMA \"{}\"", fixture.schema))
            .await;
        fixture
            .exec(&format!(
                "CREATE TABLE \"{}\".\"customers\" (id int, ssn text)",
                fixture.schema
            ))
            .await;
        fixture
            .exec(&format!(
                "INSERT INTO \"{}\".\"customers\" VALUES (1, '111-11-1111')",
                fixture.schema
            ))
            .await;
        fixture
    }

    async fn exec(&self, sql: &str) {
        self.adapter
            .execute(ExecQuery {
                sql,
                binds: &[],
                statement_timeout_ms: None,
                row_limit: 10,
            })
            .await
            .unwrap_or_else(|e| panic!("fixture SQL failed ({sql}): {e}"));
    }

    async fn drop_schema(&self) {
        self.exec(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema))
            .await;
    }
}

/// Regression: a `schema_read` grant is metadata-only. `sample_table` returns
/// rows, so it must deny — with an audited `forbidden` outcome.
#[tokio::test]
async fn schema_read_grant_cannot_sample_rows() {
    let fixture = Fixture::create().await;
    let booted = boot_gateway("metadata-only").await;

    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers" }),
    )
    .await;
    fixture.drop_schema().await;

    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["code"], "forbidden", "{body}");
    assert!(
        !resp.to_string().contains("111-11-1111"),
        "row data leaked to a schema_read-only caller: {resp}"
    );
    assert_eq!(
        latest_audit(&booted, "schema_read sample").await.outcome,
        "forbidden"
    );
}

/// The positive half of the same contract: `query_read` is the grant that
/// actually authorizes row data, and it still works.
#[tokio::test]
async fn query_read_grant_can_sample_rows() {
    let fixture = Fixture::create().await;
    let booted = boot_gateway("engineers").await;

    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers" }),
    )
    .await;
    fixture.drop_schema().await;

    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let body = payload(&resp);
    assert_eq!(body["columns"], json!(["id", "ssn"]));
    assert_eq!(body["rows"][0][0], 1);
    assert_eq!(body["rows"][0][1], "111-11-1111");
    assert_eq!(
        latest_audit(&booted, "query_read sample").await.outcome,
        "success"
    );
}

/// `require_reason` must not be dodgeable by sampling instead of querying:
/// no reason → `reason_required` and no rows; with a reason → success, and
/// the reason lands in the audit row.
#[tokio::test]
async fn require_reason_grant_blocks_sample_without_reason() {
    let fixture = Fixture::create().await;
    let booted = boot_gateway("reason-required").await;

    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers" }),
    )
    .await;
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    assert_eq!(payload(&resp)["code"], "reason_required", "{resp}");
    assert!(
        !resp.to_string().contains("111-11-1111"),
        "row data returned despite require_reason: {resp}"
    );
    let row = latest_audit(&booted, "sample without reason").await;
    assert_eq!(row.outcome, "reason_required");
    assert_eq!(row.reason, None);

    // Empty string is not a reason.
    let resp = call_sample_table(
        &booted,
        json!({ "schema": fixture.schema, "table": "customers", "reason": "" }),
    )
    .await;
    assert_eq!(payload(&resp)["code"], "reason_required", "{resp}");

    let resp = call_sample_table(
        &booted,
        json!({
            "schema": fixture.schema,
            "table": "customers",
            "reason": "ticket OPS-42 data shape check"
        }),
    )
    .await;
    fixture.drop_schema().await;

    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let row = latest_audit(&booted, "sample with reason").await;
    assert_eq!(row.outcome, "success");
    assert_eq!(
        row.reason.as_deref(),
        Some("ticket OPS-42 data shape check")
    );
}
