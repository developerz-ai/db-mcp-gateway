//! Real-DB test for `describe_schema`: create a test table in `target-db`,
//! run the catalog query through the same exec path the tool uses, assert the
//! response shape. The last test drives the tool over MCP and asserts the
//! audit row names the schema and table it read.

mod common;

use std::time::Duration;

use common::env::target_db_url;
use common::gateway::spawn_logged_in;
use common::idp::MockUser;
use common::pg_target::adapter;
use db_mcp_gateway::exec::{Access, DbAdapter, ExecQuery};
use serde_json::json;

/// Fixture DDL/DML over a plain owner connection — never through the
/// adapter, which only reads on a database without a `write_role`.
async fn ddl(sql: &str) -> Result<(), sqlx::Error> {
    let pool = sqlx::PgPool::connect(&target_db_url()).await?;
    sqlx::query(sql).execute(&pool).await.map(|_| ())
}

/// Generates a unique schema name per test run so concurrent runs (and any
/// stray data from earlier runs) don't collide.
fn fresh_schema_name() -> String {
    format!("descschema_{}", uuid::Uuid::new_v4().simple())
}

#[tokio::test]
async fn catalog_query_returns_expected_columns_and_types() {
    let a = adapter().await;
    let schema = fresh_schema_name();

    // Setup: a schema with a couple of tables of known shape.
    ddl(&format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    ddl(&format!(
        "CREATE TABLE \"{schema}\".\"users\" (id bigint NOT NULL, email text)"
    ))
    .await
    .expect("create users");
    ddl(&format!(
        "CREATE TABLE \"{schema}\".\"orders\" (id bigint NOT NULL, total numeric)"
    ))
    .await
    .expect("create orders");

    // The exact same bound query `describe_schema` runs.
    let result = a
        .execute(ExecQuery {
            sql: "SELECT table_schema, table_name, column_name, data_type, is_nullable \
                  FROM information_schema.columns \
                  WHERE table_schema = $1 \
                  ORDER BY table_name, ordinal_position",
            binds: &[&schema],
            statement_timeout_ms: None,
            row_limit: 500,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect("catalog query runs");

    // Cleanup before assertions so a failed assert still leaves the DB clean.
    let _ = ddl(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    // Expect 4 rows: users.id, users.email, orders.id, orders.total.
    assert_eq!(result.rows.len(), 4, "rows: {:?}", result.rows);
    assert_eq!(
        result.columns,
        vec![
            "table_schema",
            "table_name",
            "column_name",
            "data_type",
            "is_nullable"
        ]
    );

    // Sanity-check one row's shape.
    let first = &result.rows[0];
    assert_eq!(first[0].as_str().unwrap(), schema.as_str()); // table_schema
    assert_eq!(first[1].as_str().unwrap(), "orders"); // table_name (alphabetical < "users")
    assert_eq!(first[2].as_str().unwrap(), "id"); // column_name
    assert_eq!(first[3].as_str().unwrap(), "bigint"); // data_type
    assert_eq!(first[4].as_str().unwrap(), "NO"); // is_nullable
}

/// Filtering by table_name returns only that table's columns. Crucial because
/// `describe_schema { table: "users" }` is a common narrowing query.
#[tokio::test]
async fn table_filter_narrows_results() {
    let a = adapter().await;
    let schema = fresh_schema_name();

    ddl(&format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    ddl(&format!("CREATE TABLE \"{schema}\".\"a\" (x int)"))
        .await
        .expect("create a");
    ddl(&format!("CREATE TABLE \"{schema}\".\"b\" (y text, z bool)"))
        .await
        .expect("create b");

    let result = a
        .execute(ExecQuery {
            sql: "SELECT table_schema, table_name, column_name, data_type, is_nullable \
                  FROM information_schema.columns \
                  WHERE table_schema = $1 AND table_name = $2 \
                  ORDER BY ordinal_position",
            binds: &[&schema, "b"],
            statement_timeout_ms: None,
            row_limit: 500,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect("filtered catalog query runs");

    let _ = ddl(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    // Only the 2 columns of "b" — not "a".x.
    assert_eq!(result.rows.len(), 2);
    let names: Vec<&str> = result.rows.iter().map(|r| r[2].as_str().unwrap()).collect();
    assert_eq!(names, vec!["y", "z"]);
}

const E2E_YAML: &str = r#"
servers:
  - name: target
    kind: postgres
    description: E2E target DB
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only }

permissions:
  - group: engineers
    grants:
      - { server: target, database: app, action: schema_read }
"#;

/// The audit row of a catalog read records what was read — `schema.table` —
/// and an intent row preceded it.
#[tokio::test]
async fn describe_schema_audit_row_names_the_table_read() {
    let schema = fresh_schema_name();
    ddl(&format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    ddl(&format!("CREATE TABLE \"{schema}\".\"users\" (id int)"))
        .await
        .expect("create users");
    let booted = spawn_logged_in(
        E2E_YAML,
        MockUser {
            sub: format!("describe-{}", uuid::Uuid::new_v4().simple()),
            email: "describe-e2e@example.com".to_string(),
            groups: vec!["engineers".to_string()],
        },
    )
    .await;

    let resp: serde_json::Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap()
        .post(format!("{}/mcp", booted.url))
        .bearer_auth(&booted.bearer)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "describe_schema",
                "arguments": { "server": "target", "database": "app",
                               "schema": schema, "table": "users" }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let _ = ddl(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    assert_eq!(resp["result"]["isError"], false, "{resp}");
    let row = common::audit::latest_audit(
        &booted.state_db,
        &booted.user_sub,
        "describe_schema",
        "describe users",
    )
    .await;
    assert_eq!(row.outcome, "success");
    assert_eq!(row.sql.as_deref(), Some(format!("{schema}.users").as_str()));
    assert_eq!(
        common::audit::find_intent(&booted.state_db, &row.request_id)
            .await
            .as_deref(),
        Some("read")
    );
}
