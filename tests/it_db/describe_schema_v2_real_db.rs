//! `describe_schema` v2 over HTTP against `target-db`: every `detail` level,
//! `search`, the schema list for a call that names no schema, and the audit
//! row each call leaves. The fixture holds the shapes `full` must report: an
//! enum, an array, a primary key, a foreign key, an index, comments, a view
//! and an analysed row estimate.

use std::time::Duration;

use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::pg_target::{config_yaml, owner_url};

const YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: __TARGET_PORT__
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }

permissions:
  - group: engineers
    grants:
      - { server: target, database: app, action: schema_read }
"#;

struct Fixture {
    owner: PgPool,
    schema: String,
}

impl Fixture {
    async fn create() -> Self {
        let owner = PgPoolOptions::new()
            .max_connections(1)
            .connect(&owner_url())
            .await
            .expect("target-db reachable; run `bin/dev up`");
        let schema = format!("descv2_{}", Uuid::new_v4().simple());
        let s = &schema;
        for sql in [
            format!("CREATE SCHEMA {s}"),
            format!("CREATE TYPE {s}.mood AS ENUM ('sad', 'ok', 'happy')"),
            format!(
                "CREATE TABLE {s}.customers (id bigint PRIMARY KEY, \
                 email varchar(64) NOT NULL, feeling {s}.mood, tags text[] DEFAULT '{{}}')"
            ),
            format!(
                "CREATE TABLE {s}.orders (id bigint PRIMARY KEY, \
                 customer_id bigint NOT NULL REFERENCES {s}.customers (id), total numeric(10,2))"
            ),
            format!("CREATE INDEX orders_customer_idx ON {s}.orders (customer_id)"),
            format!("COMMENT ON TABLE {s}.customers IS 'people who buy'"),
            format!("COMMENT ON COLUMN {s}.customers.email IS 'login address'"),
            format!("CREATE VIEW {s}.big_orders AS SELECT * FROM {s}.orders WHERE total > 100"),
            format!(
                "INSERT INTO {s}.customers SELECT g, 'c' || g || '@example.com' \
                 FROM generate_series(1, 50) g"
            ),
            format!("ANALYZE {s}.customers"),
        ] {
            sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .execute(&owner)
                .await
                .unwrap_or_else(|err| panic!("fixture `{sql}`: {err}"));
        }
        Self { owner, schema }
    }

    async fn drop(self) {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.owner)
        .await
        .expect("drop fixture");
    }
}

async fn boot() -> LoggedInGateway {
    let user = MockUser {
        sub: format!("descv2-{}", Uuid::new_v4().simple()),
        email: "describe-v2@example.com".to_string(),
        groups: vec!["engineers".to_string()],
    };
    spawn_logged_in(&config_yaml(YAML), user).await
}

/// The parsed success payload of one `describe_schema` call, plus the audit
/// row it left (asserted `success`).
async fn describe(gateway: &LoggedInGateway, arguments: Value) -> (Value, Option<String>) {
    let mut args = json!({ "server": "target", "database": "app" });
    if let (Some(args), Some(extra)) = (args.as_object_mut(), arguments.as_object()) {
        args.extend(extra.clone());
    }
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "describe_schema", "arguments": args }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    assert_eq!(response["result"]["isError"], false, "{args}: {response}");
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let row = latest_audit(
        &gateway.state_db,
        &gateway.user_sub,
        "describe_schema",
        "describe",
    )
    .await;
    assert_eq!(row.outcome, "success", "{args}");
    (serde_json::from_str(text).expect("JSON payload"), row.sql)
}

fn table<'a>(payload: &'a Value, name: &str) -> &'a Value {
    payload["tables"]
        .as_array()
        .and_then(|tables| tables.iter().find(|t| t["name"] == name))
        .unwrap_or_else(|| panic!("no table {name}: {payload}"))
}

fn names(payload: &Value) -> Vec<&str> {
    payload["tables"]
        .as_array()
        .map(|tables| tables.iter().filter_map(|t| t["name"].as_str()).collect())
        .unwrap_or_default()
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn each_detail_level_answers_its_shape() {
    let fixture = Fixture::create().await;
    let gateway = boot().await;
    let s = fixture.schema.as_str();

    // Default: today's shape, no `schemas` when a schema was named.
    let (columns, sql) = describe(&gateway, json!({ "schema": s })).await;
    assert_eq!(sql.as_deref(), Some(s));
    assert_eq!(names(&columns), ["big_orders", "customers", "orders"]);
    assert_eq!(
        table(&columns, "customers")["columns"][1],
        json!({ "name": "email", "data_type": "character varying", "nullable": false })
    );
    assert!(columns.get("schemas").is_none(), "{columns}");

    let (listed, _) = describe(&gateway, json!({ "schema": s, "detail": "names" })).await;
    assert_eq!(
        listed["tables"],
        json!([
            { "schema": s, "name": "big_orders", "kind": "view" },
            { "schema": s, "name": "customers", "kind": "table" },
            { "schema": s, "name": "orders", "kind": "table" },
        ])
    );

    let (full, _) = describe(&gateway, json!({ "schema": s, "detail": "full" })).await;
    let customers = table(&full, "customers");
    assert_eq!(customers["kind"], "table");
    assert_eq!(customers["comment"], "people who buy");
    assert_eq!(customers["row_estimate"], 50);
    assert_eq!(customers["primary_key"], json!(["id"]));
    let column = |name: &str| {
        customers["columns"]
            .as_array()
            .and_then(|c| c.iter().find(|c| c["name"] == name))
            .cloned()
            .unwrap_or(Value::Null)
    };
    assert_eq!(column("email")["data_type"], "character varying(64)");
    assert_eq!(column("email")["comment"], "login address");
    assert_eq!(column("feeling")["data_type"], format!("{s}.mood"));
    assert_eq!(
        column("feeling")["enum_values"],
        json!(["sad", "ok", "happy"])
    );
    assert_eq!(column("tags")["data_type"], "text[]");
    assert_eq!(column("tags")["element_type"], "text");
    assert!(column("tags")["default"].is_string(), "{customers}");

    let orders = table(&full, "orders");
    assert_eq!(orders["foreign_keys"][0]["columns"], json!(["customer_id"]));
    assert_eq!(
        orders["foreign_keys"][0]["references"],
        json!({ "schema": s, "table": "customers", "columns": ["id"] })
    );
    let index = orders["indexes"]
        .as_array()
        .and_then(|i| i.iter().find(|i| i["name"] == "orders_customer_idx"))
        .unwrap_or_else(|| panic!("index listed: {orders}"));
    assert_eq!(index["columns"], json!(["customer_id"]));
    assert_eq!(index["unique"], false);
    assert_eq!(table(&full, "big_orders")["kind"], "view");
    assert_eq!(table(&full, "big_orders")["row_estimate"], Value::Null);

    fixture.drop().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn search_matches_table_and_column_names_across_schemas() {
    let fixture = Fixture::create().await;
    let gateway = boot().await;
    let s = fixture.schema.as_str();

    // A column name matches: the table is listed whole. No schema named:
    // every schema is searched, and the schemas are listed.
    let (found, sql) = describe(&gateway, json!({ "search": "CUSTOMER_I" })).await;
    assert_eq!(sql.as_deref(), Some("*"));
    let ours: Vec<&Value> = found["tables"]
        .as_array()
        .map(|t| t.iter().filter(|t| t["schema"] == s).collect())
        .unwrap_or_default();
    let names_found: Vec<&str> = ours.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(names_found, ["big_orders", "orders"]);
    assert_eq!(ours[1]["columns"].as_array().map(Vec::len), Some(3));
    let schemas = found["schemas"].as_array().expect("schemas listed");
    assert!(schemas.contains(&json!(s)), "{schemas:?}");
    assert!(schemas.contains(&json!("public")), "{schemas:?}");
    assert!(!schemas.contains(&json!("pg_catalog")), "{schemas:?}");

    let (found, _) = describe(
        &gateway,
        json!({ "schema": s, "search": "custom", "detail": "names" }),
    )
    .await;
    // The view matches by its `customer_id` column.
    assert_eq!(names(&found), ["big_orders", "customers", "orders"]);

    // Bound, never spliced: a quote is just a character to match.
    let (found, _) = describe(&gateway, json!({ "schema": s, "search": "' OR 1=1 --" })).await;
    assert_eq!(names(&found), Vec::<&str>::new());

    fixture.drop().await;
}

/// No schema and no search: `public`, as before, plus the schema list.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_call_without_a_schema_lists_the_schemas() {
    let fixture = Fixture::create().await;
    let gateway = boot().await;
    let (payload, sql) = describe(&gateway, json!({})).await;
    fixture.drop().await;
    assert_eq!(sql.as_deref(), Some("public"));
    assert!(
        payload["tables"]
            .as_array()
            .is_some_and(|t| t.iter().all(|t| t["schema"] == "public")),
        "{payload}"
    );
    assert!(payload["schemas"].is_array(), "{payload}");
}
