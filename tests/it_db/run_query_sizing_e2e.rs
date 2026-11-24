//! E2E for `run_query`'s sized row result: `row_limit` always, and on a
//! truncated result `truncated_by` + a paging `hint`; the caller's
//! `max_bytes` and `max_cell_bytes` caps.

use serde_json::{Value, json};

use crate::agent_walk_support::{Agent, Called, GRANT_ROW_LIMIT};
use crate::common::audit::latest_audit;

async fn run(agent: &Agent, sql: &str, extra: Value) -> Called {
    let mut args = json!({"server": "target", "database": "app", "sql": sql});
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    let called = agent.call("run_query", args).await;
    assert!(!called.is_error(), "{:?}", called.response);
    agent.assert_audited(&called, "success").await;
    called
}

const SERIES: &str = "SELECT g::int8 AS n FROM generate_series(1, 100) g";

#[tokio::test]
#[serial_test::parallel(world)]
async fn truncation_says_which_cap_cut_and_how_to_page() {
    let agent = Agent::boot().await;

    // The caller's own `limit`: a larger one returns more.
    let called = run(&agent, SERIES, json!({"limit": 10})).await;
    let body = &called.payload;
    assert_eq!(body["rows"].as_array().unwrap().len(), 10);
    assert_eq!(body["truncated"], true);
    assert_eq!(body["truncated_by"], "limit");
    assert_eq!(body["row_limit"], 10);
    assert!(
        body["hint"].as_str().unwrap().contains("WHERE key >"),
        "{body}"
    );
    let row = latest_audit(
        &agent.gateway.state_db,
        &agent.gateway.user_sub,
        "run_query",
        "limit",
    )
    .await;
    assert_eq!((row.row_count, row.truncated), (Some(10), Some(true)));

    // No `limit`: the default 1000 is clipped to the grant's 50.
    let called = run(&agent, SERIES, json!({})).await;
    let body = &called.payload;
    assert_eq!(body["rows"].as_array().unwrap().len(), 50);
    assert_eq!(body["truncated_by"], "grant_row_limit");
    assert_eq!(body["row_limit"], GRANT_ROW_LIMIT);

    // Everything fits: no cause, no hint, the limit still reported.
    let called = run(&agent, "SELECT 1::int8 AS n", json!({})).await;
    let body = &called.payload;
    assert_eq!(body["truncated"], false);
    assert_eq!(body["row_limit"], GRANT_ROW_LIMIT);
    for absent in ["truncated_by", "hint", "cells_truncated"] {
        assert!(body.get(absent).is_none(), "{absent}: {body}");
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn max_bytes_keeps_the_leading_rows_that_fit() {
    let agent = Agent::boot().await;
    // `[[1],[2],[3],[4]]` is 17 bytes; a fifth row makes it 21.
    let called = run(&agent, SERIES, json!({"max_bytes": 20})).await;
    let body = &called.payload;
    assert_eq!(body["rows"], json!([[1], [2], [3], [4]]));
    assert_eq!(body["truncated"], true);
    assert_eq!(body["truncated_by"], "byte_cap");
    assert!(
        body["hint"].as_str().unwrap().contains("max_cell_bytes"),
        "{body}"
    );
    let row = latest_audit(
        &agent.gateway.state_db,
        &agent.gateway.user_sub,
        "run_query",
        "bytes",
    )
    .await;
    assert_eq!(row.row_count, Some(4), "the audit row counts the rows sent");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn max_cell_bytes_replaces_an_oversized_cell_with_the_marker() {
    let agent = Agent::boot().await;
    let sql = "SELECT repeat('x', 100) AS big, 'ok' AS small";
    let called = run(&agent, sql, json!({"max_cell_bytes": 10})).await;
    let body = &called.payload;
    assert_eq!(
        body["rows"],
        json!([[{"$dbmcp_truncated": {"bytes": 102, "preview": "xxxxxxxxxx"}}, "ok"]])
    );
    assert_eq!(body["cells_truncated"], 1);
    assert_eq!(body["truncated"], false, "capping a cell drops no row");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_zero_byte_cap_is_an_argument_error() {
    let agent = Agent::boot().await;
    for cap in ["max_bytes", "max_cell_bytes"] {
        let mut args = json!({"server": "target", "database": "app", "sql": "SELECT 1"});
        args[cap] = json!(0);
        let called = agent.call("run_query", args).await;
        assert_eq!(
            called.response["error"]["code"], -32602,
            "{cap}: {:?}",
            called.response
        );
        agent.assert_audited(&called, "invalid_arguments").await;
    }
}
