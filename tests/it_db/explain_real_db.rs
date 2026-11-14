//! Real-DB test for `explain`: confirms `EXPLAIN (FORMAT JSON) SELECT ...`
//! against the live `target-db` returns a parseable plan with the structure
//! the tool's `extract_plan` expects.

use crate::common::pg_target::adapter;
use db_mcp_gateway::exec::{Access, DbAdapter, ExecQuery};

/// The shape `explain::extract_plan` relies on: one row, one column, with
/// JSON-shaped content. Postgres returns it as a `json` column which sqlx
/// can decode directly as a Value, OR as text-with-JSON-content depending on
/// the version path; the tool's `extract_plan` handles both.
#[tokio::test]
async fn explain_returns_parseable_json_plan() {
    let a = adapter().await;
    let result = a
        .execute(ExecQuery {
            sql: "EXPLAIN (FORMAT JSON) SELECT 1",
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 10,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect("EXPLAIN runs");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].len(), 1);

    // The cell is either already-parsed JSON or a string containing JSON —
    // mirror `explain::extract_plan`'s tolerance.
    let cell = &result.rows[0][0];
    let plan: serde_json::Value = match cell {
        serde_json::Value::String(s) => serde_json::from_str(s).expect("plan text is JSON"),
        other => other.clone(),
    };
    assert!(
        plan.is_array(),
        "EXPLAIN (FORMAT JSON) returns an array: {plan}"
    );
    assert!(
        plan[0]["Plan"]["Node Type"].is_string(),
        "plan[0].Plan.Node Type must be a string: {plan}"
    );
}
