//! Real-DB test for `describe_schema`: create a test table in `target-db`,
//! run the catalog query through the same exec path the tool uses, assert the
//! response shape. Doesn't exercise auth / MCP transport — those land in the
//! combined inspection-tools e2e in slice 4.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{DbAdapter, ExecError, ExecQuery, ExecResult, PgAdapter};

const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 5434;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";

fn server() -> Server {
    Server {
        name: "target".to_string(),
        kind: ServerKind::Postgres,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: TARGET_PORT,
        tls: Tls::Insecure,
        databases: vec![database()],
    }
}

fn database() -> Database {
    Database {
        name: TARGET_DB.to_string(),
        role: TARGET_USER.to_string(),
        password: Password::Literal(TARGET_PASSWORD.to_string()),
        description: String::new(),
        auth_database: None,
    }
}

async fn adapter() -> PgAdapter {
    PgAdapter::open(&server(), &database())
        .await
        .expect("target-db reachable; run `bin/dev up`")
}

async fn run(a: &PgAdapter, sql: &str) -> Result<ExecResult, ExecError> {
    a.execute(ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 10,
    })
    .await
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
    run(&a, &format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    run(
        &a,
        &format!("CREATE TABLE \"{schema}\".\"users\" (id bigint NOT NULL, email text)"),
    )
    .await
    .expect("create users");
    run(
        &a,
        &format!("CREATE TABLE \"{schema}\".\"orders\" (id bigint NOT NULL, total numeric)"),
    )
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
        })
        .await
        .expect("catalog query runs");

    // Cleanup before assertions so a failed assert still leaves the DB clean.
    let _ = run(&a, &format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

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

    run(&a, &format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    run(&a, &format!("CREATE TABLE \"{schema}\".\"a\" (x int)"))
        .await
        .expect("create a");
    run(
        &a,
        &format!("CREATE TABLE \"{schema}\".\"b\" (y text, z bool)"),
    )
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
        })
        .await
        .expect("filtered catalog query runs");

    let _ = run(&a, &format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    // Only the 2 columns of "b" — not "a".x.
    assert_eq!(result.rows.len(), 2);
    let names: Vec<&str> = result.rows.iter().map(|r| r[2].as_str().unwrap()).collect();
    assert_eq!(names, vec!["y", "z"]);
}
