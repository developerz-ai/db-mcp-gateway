//! Real-DB tests for `sample_table`: setup a table, sample it through the
//! exec layer the tool uses, and assert the shape. Identifier-safety unit
//! tests in `src/tools/sample_table.rs` already cover the regex; this file
//! proves the happy-path SQL works against a live Postgres.

use crate::common::env::target_db_url;
use crate::common::pg_target::adapter;
use db_mcp_gateway::exec::{Access, DbAdapter, ExecQuery};

/// Fixture DDL/DML over a plain owner connection — never through the
/// adapter, which only reads on a database without a `write_role`.
async fn ddl(sql: &str) -> Result<(), sqlx::Error> {
    let pool = sqlx::PgPool::connect(&target_db_url()).await?;
    sqlx::query(sql).execute(&pool).await.map(|_| ())
}

fn fresh_schema_name() -> String {
    format!("sampletbl_{}", uuid::Uuid::new_v4().simple())
}

/// The exact same SQL `sample_table` would build, once identifiers have
/// passed the regex check. Confirms identifier interpolation + LIMIT
/// interpolation produce a query Postgres actually accepts and that the
/// row-cap/truncation semantics carry through from the adapter.
#[tokio::test]
async fn sample_returns_rows_with_truncation_flag() {
    let a = adapter().await;
    let schema = fresh_schema_name();

    ddl(&format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    ddl(&format!(
        "CREATE TABLE \"{schema}\".\"events\" (id int, name text)"
    ))
    .await
    .expect("create events");
    ddl(&format!(
        "INSERT INTO \"{schema}\".\"events\" \
             SELECT g, 'event-' || g FROM generate_series(1, 100) g"
    ))
    .await
    .expect("seed events");

    // Cap at 5 rows; mirror the LIMIT+1 trick `sample_table` uses so the
    // gateway-side truncation flag fires when more rows exist.
    let sql = format!("SELECT * FROM \"{schema}\".\"events\" LIMIT 6");
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 5,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect("sample SELECT runs");

    let _ = ddl(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    assert_eq!(result.rows.len(), 5);
    assert!(
        result.truncated,
        "expected truncated=true when more rows exist"
    );
    assert_eq!(result.columns, vec!["id".to_string(), "name".to_string()]);
}

/// Quoted-identifier SQL doesn't trip on Postgres' case-folding: an
/// unquoted `EVENTS` would be lowercased, but `"EVENTS"` is exact. This is
/// the same path `sample_table` takes when the regex accepts an uppercase
/// table name.
#[tokio::test]
async fn quoted_identifiers_are_case_sensitive() {
    let a = adapter().await;
    let schema = fresh_schema_name();

    ddl(&format!("CREATE SCHEMA \"{schema}\""))
        .await
        .expect("create schema");
    ddl(&format!("CREATE TABLE \"{schema}\".\"MixedCase\" (x int)"))
        .await
        .expect("create MixedCase");
    ddl(&format!(
        "INSERT INTO \"{schema}\".\"MixedCase\" VALUES (1), (2), (3)"
    ))
    .await
    .expect("seed");

    let sql = format!("SELECT * FROM \"{schema}\".\"MixedCase\" LIMIT 10");
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 10,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect("quoted identifier query runs");

    let _ = ddl(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await;

    assert_eq!(result.rows.len(), 3);
}
