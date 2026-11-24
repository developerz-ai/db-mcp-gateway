//! The golden agent walk: the calls an agent makes against an unfamiliar
//! database, each answer carrying enough to make the next call right —
//! discover → describe → a typo'd column (hint: describe_schema) → fix →
//! a truncated result (truncated_by + paging hint) → follow the hint → a
//! timeout (limit + hint: explain) → a server it may not use (hint:
//! list_servers). Every step is audited under its own `request_id`.

use serde_json::json;

use crate::agent_walk_support::{Agent, Fixture, GRANT_ROW_LIMIT, GRANT_TIMEOUT_MS};

#[tokio::test]
#[serial_test::parallel(world)]
async fn agent_walk_from_discovery_to_paging() {
    let agent = Agent::boot().await;
    let fixture = Fixture::create(120).await;
    let items = format!("\"{}\".items", fixture.schema);
    let run = |sql: String| json!({"server": "target", "database": "app", "sql": sql});

    // 1. Discover: the granted server is listed, the ungranted one is not.
    let called = agent.call("list_servers", json!({})).await;
    assert!(!called.is_error(), "{:?}", called.response);
    let listed = called.payload.to_string();
    assert!(listed.contains("\"target\""), "{listed}");
    assert!(!listed.contains("\"hidden\""), "{listed}");
    agent.assert_audited(&called, "success").await;

    // 2. Describe the table: its real column names.
    let args = json!({
        "server": "target", "database": "app", "schema": fixture.schema, "table": "items"
    });
    let called = agent.call("describe_schema", args).await;
    assert!(!called.is_error(), "{:?}", called.response);
    let described = called.payload.to_string();
    assert!(described.contains("\"label\""), "{described}");
    agent.assert_audited(&called, "success").await;

    // 3. A typo'd column: undefined_object names it and points back at step 2.
    let called = agent
        .call("run_query", run(format!("SELECT id, lable FROM {items}")))
        .await;
    let body = &called.payload;
    assert_eq!(body["code"], "undefined_object", "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("lable"),
        "{body}"
    );
    assert!(
        body["hint"].as_str().unwrap().contains("describe_schema"),
        "{body}"
    );
    assert_eq!(body["retryable"], false);
    agent.assert_audited(&called, "undefined_object").await;

    // 4. Fixed — and cut at the grant's row limit, with keyset guidance.
    let sql = format!("SELECT id, label FROM {items} ORDER BY id");
    let called = agent.call("run_query", run(sql)).await;
    let body = &called.payload;
    assert!(!called.is_error(), "{body}");
    assert_eq!(body["rows"].as_array().unwrap().len(), 50);
    assert_eq!(body["truncated_by"], "grant_row_limit");
    assert_eq!(body["row_limit"], GRANT_ROW_LIMIT);
    assert!(
        body["hint"].as_str().unwrap().contains("WHERE key >"),
        "{body}"
    );
    let last_id = body["rows"][49][0].as_i64().unwrap();
    agent.assert_audited(&called, "success").await;

    // 5. Follow the hint: the next page starts after the last key.
    let sql = format!("SELECT id, label FROM {items} WHERE id > {last_id} ORDER BY id");
    let mut args = run(sql);
    args["limit"] = json!(10);
    let called = agent.call("run_query", args).await;
    let body = &called.payload;
    assert_eq!(body["rows"][0][0], last_id + 1, "{body}");
    assert_eq!(body["truncated_by"], "limit");
    agent.assert_audited(&called, "success").await;

    // 6. Too slow: the budget is named and explain is the next step.
    let sql = format!("SELECT pg_sleep(2), id FROM {items} LIMIT 1");
    let called = agent.call("run_query", run(sql)).await;
    let body = &called.payload;
    assert_eq!(body["code"], "timeout", "{body}");
    assert_eq!(body["limit"]["value"], GRANT_TIMEOUT_MS);
    assert!(body["hint"].as_str().unwrap().contains("explain"), "{body}");
    agent.assert_audited(&called, "timeout").await;

    // 7. A server it may not use: forbidden, pointing at discovery.
    let mut args = run("SELECT 1".to_owned());
    args["server"] = json!("hidden");
    let called = agent.call("run_query", args).await;
    let body = &called.payload;
    assert_eq!(body["code"], "forbidden", "{body}");
    assert!(
        body["hint"].as_str().unwrap().contains("list_servers"),
        "{body}"
    );
    agent.assert_audited(&called, "forbidden").await;

    fixture.drop_schema().await;
}
