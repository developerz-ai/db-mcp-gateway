//! Real-DB tests for the byte cap: what a result may cost the gateway to
//! hold, weighed before it is held. Target: `target-db` (`bin/dev up`).

use db_mcp_gateway::exec::{Access, DbAdapter, ExecQuery, ExecResult, PgAdapter};
use serde_json::json;
use uuid::Uuid;

use crate::common::pg_target::adapter;

async fn run(adapter: &PgAdapter, sql: &str) -> ExecResult {
    let query = ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 100,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    };
    adapter
        .execute(query)
        .await
        .unwrap_or_else(|err| panic!("`{sql}` runs: {err:?}"))
}

/// The byte cap weighs what the gateway holds, not the wire form: two
/// million `int4`s are 16 MB on the wire and several times that decoded.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_row_is_weighed_by_its_decoded_size() {
    let a = adapter().await;
    let result = run(
        &a,
        "SELECT array_agg(g::int4) AS big FROM generate_series(1, 2000000) g",
    )
    .await;
    assert!(result.truncated);
    assert!(result.rows.is_empty());
    assert_eq!(result.columns, vec!["big".to_string()]);
}

/// A JSON cell of small scalars fits the wire check and decodes to many
/// times that. It is weighed while it parses, so the parse stops at the cap
/// instead of building 160 MB to measure it.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_json_cell_is_weighed_while_it_parses() {
    let a = adapter().await;
    for sql in [
        "SELECT array_to_json(array_fill(0, ARRAY[5000000])) AS big",
        "SELECT to_jsonb(array_fill(0, ARRAY[3000000])) AS big",
    ] {
        let result = run(&a, sql).await;
        assert!(result.truncated, "{sql}");
        assert!(result.rows.is_empty(), "{sql}");
        assert_eq!(result.columns, vec!["big".to_string()]);
    }
    // A cell that fits is unchanged, `json` and `jsonb` alike.
    let small = run(
        &a,
        r#"SELECT '{"b": [1, "x", null]}'::json, '{"b": [1, "x", null]}'::jsonb"#,
    )
    .await;
    let want = json!({"b": [1, "x", null]});
    assert_eq!(small.rows[0], vec![want.clone(), want]);
}

/// One cell past the byte cap is refused from its wire length alone.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_cell_past_the_byte_cap_is_truncated_away() {
    let a = adapter().await;
    let result = run(&a, "SELECT repeat('x', 40000000) AS big").await;
    assert!(result.truncated);
    assert!(result.rows.is_empty());
}
