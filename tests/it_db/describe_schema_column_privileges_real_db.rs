//! `describe_schema` `detail: full` against `target-db`, as a read role
//! granted only some columns: a primary key, foreign key or index touching
//! a column the role cannot see is left out whole, so no key list or index
//! definition names a hidden column.

use std::time::Duration;

use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::spawn_logged_in;
use crate::common::idp::MockUser;
use crate::common::pg_target::{config_yaml, owner_url};

const PASSWORD: &str = "colpriv-dev-only";

/// A throwaway schema, and a login role holding column privileges only.
struct Fixture {
    owner: PgPool,
    schema: String,
    role: String,
}

impl Fixture {
    async fn create() -> Self {
        let owner = PgPoolOptions::new()
            .max_connections(1)
            .connect(&owner_url())
            .await
            .expect("target-db reachable; run `bin/dev up`");
        let id = Uuid::new_v4().simple();
        let fixture = Self {
            owner,
            schema: format!("colpriv_{id}"),
            role: format!("colpriv_{id}"),
        };
        let (s, r) = (&fixture.schema, &fixture.role);
        for sql in [
            format!("CREATE ROLE {r} LOGIN PASSWORD '{PASSWORD}'"),
            format!("CREATE SCHEMA {s}"),
            format!("CREATE TABLE {s}.accounts (id bigint PRIMARY KEY, ssn text UNIQUE)"),
            format!("CREATE INDEX accounts_lower_ssn_idx ON {s}.accounts (lower(ssn))"),
            format!("CREATE INDEX accounts_partial_idx ON {s}.accounts (id) WHERE ssn IS NOT NULL"),
            format!("CREATE INDEX accounts_id_idx ON {s}.accounts (id)"),
            format!(
                "CREATE TABLE {s}.orders (id bigint, hidden bigint, \
                 account_id bigint REFERENCES {s}.accounts (id), \
                 account_ssn text REFERENCES {s}.accounts (ssn), \
                 hidden_account bigint REFERENCES {s}.accounts (id), \
                 PRIMARY KEY (id, hidden))"
            ),
            format!("CREATE INDEX orders_account_idx ON {s}.orders (account_id)"),
            format!("CREATE INDEX orders_include_idx ON {s}.orders (account_id) INCLUDE (hidden)"),
            format!("GRANT USAGE ON SCHEMA {s} TO {r}"),
            format!("GRANT SELECT (id) ON {s}.accounts TO {r}"),
            format!("GRANT SELECT (id, account_id, account_ssn) ON {s}.orders TO {r}"),
        ] {
            fixture.exec(&sql).await;
        }
        fixture
    }

    async fn exec(&self, sql: &str) {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&self.owner)
            .await
            .unwrap_or_else(|err| panic!("fixture `{sql}`: {err}"));
    }

    async fn drop(self) {
        self.exec(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await;
        self.exec(&format!("DROP OWNED BY {}", self.role)).await;
        self.exec(&format!("DROP ROLE {}", self.role)).await;
    }
}

/// The `full` payload for the fixture schema, read as the fixture's role,
/// and the audit row's `(outcome, sql)`.
async fn describe_full(fixture: &Fixture) -> (Value, String, Option<String>) {
    let yaml = format!(
        r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - {{ name: app, role: {role}, password: {PASSWORD} }}

permissions:
  - group: engineers
    grants:
      - {{ server: target, database: app, action: schema_read }}
"#,
        role = fixture.role
    );
    let user = MockUser {
        sub: format!("colpriv-{}", Uuid::new_v4().simple()),
        email: "colpriv@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    let gateway = spawn_logged_in(&config_yaml(&yaml), user).await;
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "describe_schema", "arguments": {
                "server": "target", "database": "app",
                "schema": fixture.schema, "detail": "full" } }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool result: {response}"));
    let row = latest_audit(
        &gateway.state_db,
        &gateway.user_sub,
        "describe_schema",
        "full",
    )
    .await;
    (
        serde_json::from_str(text).expect("JSON payload"),
        row.outcome.to_string(),
        row.sql,
    )
}

fn table<'a>(payload: &'a Value, name: &str) -> &'a Value {
    payload["tables"]
        .as_array()
        .and_then(|tables| tables.iter().find(|t| t["name"] == name))
        .unwrap_or_else(|| panic!("no table {name}: {payload}"))
}

fn names(entries: &Value) -> Vec<&str> {
    let mut names: Vec<&str> = entries
        .as_array()
        .map(|e| e.iter().filter_map(|e| e["name"].as_str()).collect())
        .unwrap_or_default();
    names.sort_unstable();
    names
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn keys_and_indexes_on_hidden_columns_are_left_out() {
    let fixture = Fixture::create().await;
    let (payload, outcome, sql) = describe_full(&fixture).await;
    let schema = fixture.schema.clone();
    fixture.drop().await;

    assert_eq!(outcome, "success", "{payload}");
    assert_eq!(sql.as_deref(), Some(schema.as_str()));

    let accounts = table(&payload, "accounts");
    assert_eq!(names(&accounts["columns"]), ["id"]);
    assert_eq!(accounts["primary_key"], json!(["id"]));
    // The UNIQUE (ssn), expression and partial indexes all read `ssn`.
    assert_eq!(
        names(&accounts["indexes"]),
        ["accounts_id_idx", "accounts_pkey"]
    );
    assert!(!accounts.to_string().contains("ssn"), "{accounts}");

    let orders = table(&payload, "orders");
    assert_eq!(
        names(&orders["columns"]),
        ["account_id", "account_ssn", "id"]
    );
    // `hidden` is in the primary key: the key is left out, not shortened.
    assert_eq!(orders["primary_key"], Value::Null, "{orders}");
    // `account_ssn` references hidden `accounts.ssn`; `hidden_account` is
    // itself hidden. Only the fully visible key remains.
    assert_eq!(names(&orders["foreign_keys"]), ["orders_account_id_fkey"]);
    assert_eq!(
        orders["foreign_keys"][0]["references"]["columns"],
        json!(["id"])
    );
    // `orders_pkey` and the INCLUDE index touch `hidden`.
    assert_eq!(names(&orders["indexes"]), ["orders_account_idx"]);
    assert!(!orders.to_string().contains("hidden"), "{orders}");
}
