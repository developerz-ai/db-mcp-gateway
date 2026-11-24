//! E2E for `sample_table`'s `columns` argument and its sized row result.

use serde_json::{Value, json};

use crate::agent_walk_support::{Agent, Called, Fixture};

async fn sample(agent: &Agent, fixture: &Fixture, extra: Value) -> Called {
    let mut args = json!({
        "server": "target",
        "database": "app",
        "schema": fixture.schema,
        "table": "items",
        "limit": 3
    });
    for (key, value) in extra.as_object().unwrap() {
        args[key] = value.clone();
    }
    agent.call("sample_table", args).await
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn columns_keep_the_named_columns_in_order() {
    let agent = Agent::boot().await;
    let fixture = Fixture::create(30).await;

    let called = sample(&agent, &fixture, json!({"columns": ["label", "id"]})).await;
    assert!(!called.is_error(), "{:?}", called.response);
    let body = &called.payload;
    assert_eq!(body["columns"], json!(["label", "id"]));
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].as_array().unwrap().len(), 2);
    assert!(rows[0][0].as_str().unwrap().starts_with("item-"), "{body}");
    assert_eq!(body["truncated_by"], "limit");
    assert_eq!(body["row_limit"], 3);
    agent.assert_audited(&called, "success").await;

    // The 200-byte `blob` cells become markers.
    let called = sample(&agent, &fixture, json!({"max_cell_bytes": 20})).await;
    let body = &called.payload;
    assert_eq!(body["cells_truncated"], 3, "{body}");
    assert_eq!(body["rows"][0][2]["$dbmcp_truncated"]["bytes"], 202);
    agent.assert_audited(&called, "success").await;

    fixture.drop_schema().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn an_unknown_column_is_undefined_object() {
    let agent = Agent::boot().await;
    let fixture = Fixture::create(3).await;

    let called = sample(&agent, &fixture, json!({"columns": ["id", "lable"]})).await;
    assert!(called.is_error(), "{:?}", called.response);
    let body = &called.payload;
    assert_eq!(body["code"], "undefined_object");
    assert!(
        body["message"].as_str().unwrap().contains("lable"),
        "{body}"
    );
    assert!(
        body["hint"].as_str().unwrap().contains("describe_schema"),
        "{body}"
    );
    agent.assert_audited(&called, "undefined_object").await;

    fixture.drop_schema().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_bad_columns_list_is_an_argument_error() {
    let agent = Agent::boot().await;
    let fixture = Fixture::create(1).await;
    for columns in [json!([]), json!(["id", "id"]), json!(["id; drop"])] {
        let called = sample(&agent, &fixture, json!({ "columns": columns })).await;
        assert_eq!(
            called.response["error"]["code"], -32602,
            "{columns}: {:?}",
            called.response
        );
        agent.assert_audited(&called, "invalid_arguments").await;
    }
    fixture.drop_schema().await;
}
