//! Plumbing shared by the agent-surface e2e tests (`agent_walk_e2e`,
//! `tool_errors_body_e2e`, `run_query_sizing_e2e`, `sample_table_columns_e2e`,
//! `tool_error_codes_e2e`):
//! a logged-in gateway on the live target, one MCP call that returns the
//! payload and the gateway `request_id`, and a throwaway fixture schema.

// audit-guard: exempt — harness, not a test: every caller asserts each call's own row by `request_id` through `Agent::assert_audited` / `Agent::audit_of`.

use std::time::Duration;

use serde_json::{Value, json};

use crate::common::audit::calls_for_request;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::{config_yaml, owner_url};

/// `target/app` under a 300 ms statement timeout and a 50-row grant cap;
/// `hidden/app` exists but the caller has no grant on it.
const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only
  - name: hidden
    kind: postgres
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only

permissions:
  - group: engineers
    grants:
      - server: target
        database: app
        action: query_read
        constraints:
          statement_timeout_ms: 300
          row_limit: 50
"#;

/// The grant's statement timeout in `YAML`.
pub const GRANT_TIMEOUT_MS: u64 = 300;
/// The grant's row limit in `YAML`.
pub const GRANT_ROW_LIMIT: u64 = 50;

/// One tool call's answer: the gateway `request_id` (the `x-request-id`
/// header, also `audit_calls.request_id`), the JSON-RPC response, and the
/// parsed text payload when the response is a tool result.
#[derive(Debug)]
pub struct Called {
    pub request_id: String,
    pub response: Value,
    pub payload: Value,
}

impl Called {
    pub fn is_error(&self) -> bool {
        self.response["result"]["isError"] == true
    }
}

#[derive(Debug)]
pub struct Agent {
    pub gateway: LoggedInGateway,
    client: reqwest::Client,
}

impl Agent {
    pub async fn boot() -> Self {
        Self::boot_with(YAML).await
    }

    /// An agent on a gateway running `yaml` (a [`config_yaml`] template) that
    /// grants the `engineers` group.
    pub async fn boot_with(yaml: &str) -> Self {
        let user = MockUser {
            sub: format!("agent-walk-{}", uuid::Uuid::new_v4().simple()),
            email: "agent-walk@example.com".to_string(),
            groups: vec!["engineers".to_string()],
        };
        let gateway = spawn_logged_in(&config_yaml(yaml), user).await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap();
        Self { gateway, client }
    }

    pub async fn call(&self, tool: &str, arguments: Value) -> Called {
        let http = self
            .client
            .post(format!("{}/mcp", self.gateway.url))
            .bearer_auth(&self.gateway.bearer)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            }))
            .send()
            .await
            .unwrap();
        let request_id = http.headers()["x-request-id"].to_str().unwrap().to_owned();
        let response: Value = http.json().await.unwrap();
        let payload = response["result"]["content"][0]["text"]
            .as_str()
            .map_or(Value::Null, |text| serde_json::from_str(text).unwrap());
        Called {
            request_id,
            response,
            payload,
        }
    }

    /// The one completion row of `called`, as `(outcome, error_message)`.
    pub async fn audit_of(&self, called: &Called) -> (String, Option<String>) {
        let rows = calls_for_request(&self.gateway.state_db, &called.request_id).await;
        assert_eq!(rows.len(), 1, "one audit row per call: {rows:?}");
        rows.into_iter().next().unwrap()
    }

    /// Assert `called` was audited with `outcome`.
    pub async fn assert_audited(&self, called: &Called, outcome: &str) {
        let (audited, message) = self.audit_of(called).await;
        assert_eq!(audited, outcome, "audit row for {called:?}: {message:?}");
    }
}

/// A fresh schema holding `items(id int8 primary key, label text, blob text)`
/// with `rows` rows; dropped by [`Fixture::drop_schema`].
#[derive(Debug)]
pub struct Fixture {
    pub schema: String,
}

impl Fixture {
    pub async fn create(rows: u32) -> Self {
        let schema = format!("walk_{}", uuid::Uuid::new_v4().simple());
        owner_exec(&format!(
            "CREATE SCHEMA \"{schema}\"; \
             CREATE TABLE \"{schema}\".items (id int8 PRIMARY KEY, label text, blob text); \
             INSERT INTO \"{schema}\".items \
               SELECT g, 'item-' || g, repeat('x', 200) FROM generate_series(1, {rows}) g"
        ))
        .await;
        Self { schema }
    }

    pub async fn drop_schema(self) {
        owner_exec(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema)).await;
    }
}

async fn owner_exec(sql: &str) {
    let pool = sqlx::PgPool::connect(&owner_url()).await.unwrap();
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(&pool)
        .await
        .unwrap_or_else(|err| panic!("fixture SQL failed: {err}"));
}
