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
            format!(
                "CREATE TABLE {s}.ledger (id bigint, payroll_code text, \
                 code_len int GENERATED ALWAYS AS (length(payroll_code)) STORED, \
                 id_twice bigint GENERATED ALWAYS AS (id * 2) STORED)"
            ),
            format!("CREATE TABLE {s}.vault (id bigint, salary_band text)"),
            format!("CREATE SCHEMA {s}_sealed"),
            format!("CREATE TABLE {s}_sealed.keys (id bigint PRIMARY KEY)"),
            format!(
                "CREATE TABLE {s}.refs (id bigint, key_id bigint REFERENCES {s}_sealed.keys (id))"
            ),
            format!("GRANT SELECT (id) ON {s}_sealed.keys TO {r}"),
            format!("GRANT SELECT (id, key_id) ON {s}.refs TO {r}"),
            format!("GRANT USAGE ON SCHEMA {s} TO {r}"),
            format!("GRANT SELECT (id, code_len, id_twice) ON {s}.ledger TO {r}"),
            format!("GRANT SELECT (id) ON {s}.vault TO {r}"),
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
        self.exec(&format!(
            "DROP SCHEMA {s}, {s}_sealed CASCADE",
            s = self.schema
        ))
        .await;
        self.exec(&format!("DROP OWNED BY {}", self.role)).await;
        self.exec(&format!("DROP ROLE {}", self.role)).await;
    }
}

/// The `full` payload for the fixture schema, read as the fixture's role,
/// and the audit row's `(outcome, sql)`.
async fn describe_full(fixture: &Fixture) -> (Value, String, Option<String>) {
    describe(fixture, "full", None).await
}

/// One `describe_schema` call over the fixture schema at `detail`, searched
/// for `search` when given, as the fixture's role.
async fn describe(
    fixture: &Fixture,
    detail: &str,
    search: Option<&str>,
) -> (Value, String, Option<String>) {
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
    let mut arguments = json!({
        "server": "target", "database": "app",
        "schema": fixture.schema, "detail": detail });
    if let Some(search) = search {
        arguments["search"] = json!(search);
    }
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "describe_schema", "arguments": arguments }
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
        detail,
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

/// A foreign key into a schema the role holds no USAGE on is left out, even
/// with column privileges on both sides: listing it would name that schema
/// and table.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_foreign_key_into_a_schema_without_usage_is_left_out() {
    let fixture = Fixture::create().await;
    let (payload, outcome, _) = describe_full(&fixture).await;
    let sealed = format!("{}_sealed", fixture.schema);
    fixture.drop().await;

    assert_eq!(outcome, "success", "{payload}");
    let refs = table(&payload, "refs");
    assert_eq!(names(&refs["columns"]), ["id", "key_id"]);
    assert_eq!(refs["foreign_keys"], json!([]), "{refs}");
    assert!(!payload.to_string().contains(&sealed), "{payload}");
}

/// A search term matches only names the role can see: `vault` holds a
/// hidden `salary_band`, so searching `salary` must not list it.
#[tokio::test]
#[serial_test::parallel(world)]
async fn search_never_matches_a_hidden_column() {
    let fixture = Fixture::create().await;
    let mut found = Vec::new();
    for detail in ["names", "full", "columns"] {
        let (payload, outcome, _) = describe(&fixture, detail, Some("salary")).await;
        assert_eq!(outcome, "success", "{detail}: {payload}");
        found.push((detail, payload));
    }
    let (visible, _, _) = describe(&fixture, "names", Some("code_len")).await;
    fixture.drop().await;

    for (detail, payload) in found {
        assert!(
            !payload.to_string().contains("vault"),
            "{detail}: {payload}"
        );
    }
    assert!(visible.to_string().contains("ledger"), "{visible}");
}

/// A visible generated column whose expression reads a hidden column has
/// no `default`: the expression would name the hidden column.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_generated_expression_over_a_hidden_column_is_left_out() {
    let fixture = Fixture::create().await;
    let (payload, outcome, _) = describe_full(&fixture).await;
    fixture.drop().await;

    assert_eq!(outcome, "success", "{payload}");
    let ledger = table(&payload, "ledger");
    assert_eq!(names(&ledger["columns"]), ["code_len", "id", "id_twice"]);
    assert!(!ledger.to_string().contains("payroll"), "{ledger}");
    let column = |name: &str| {
        ledger["columns"]
            .as_array()
            .and_then(|c| c.iter().find(|c| c["name"] == name))
            .cloned()
            .unwrap_or_else(|| panic!("no column {name}: {ledger}"))
    };
    assert_eq!(column("code_len").get("default"), None, "{ledger}");
    // Every column `id_twice` reads is visible: its expression stays.
    assert!(
        column("id_twice")["default"]
            .as_str()
            .is_some_and(|d| d.contains("id")),
        "{ledger}"
    );
}
