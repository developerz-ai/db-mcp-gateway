//! Mongo `system.*` collections against `target-mongo`: `run_query` refuses
//! a data read of one `forbidden_sql`, and `describe_schema` `full` lists one
//! without sampling it. The audit row of a `full` call that samples says so.

use std::time::Duration;

use mongodb::bson::doc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mongo_target::{TARGET_DB, drop_collection, side_client, unique_collection};

const YAML: &str = r#"
servers:
  - name: mongo
    kind: mongo
    description: E2E target Mongo
    host: localhost
    port: 27018
    tls: insecure
    databases:
      - { name: app, role: app, password: app-dev-only, auth_database: admin }

permissions:
  - group: readers
    grants:
      - { server: mongo, database: app, action: query_read }
  - group: capped-readers
    grants:
      - server: mongo
        database: app
        action: query_read
        constraints:
          row_limit: 5
  - group: metadata-only
    grants:
      - { server: mongo, database: app, action: schema_read }
"#;

async fn boot(group: &str) -> LoggedInGateway {
    let user = MockUser {
        sub: format!("msys-{}", Uuid::new_v4().simple()),
        email: "mongo-system@example.com".to_string(),
        groups: vec![group.to_string()],
    };
    spawn_logged_in(YAML, user).await
}

/// One `tools/call`, its tool result, and the audit row's `(outcome, sql)`.
async fn call(gateway: &LoggedInGateway, tool: &str, arguments: Value) -> (Value, String, String) {
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
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
    let row = latest_audit(&gateway.state_db, &gateway.user_sub, tool, tool).await;
    (
        serde_json::from_str(text).expect("JSON payload"),
        row.outcome.to_string(),
        row.sql.unwrap_or_default(),
    )
}

/// A collection of one document, and a view over it — the view makes the
/// database hold `system.views`.
async fn seeded() -> (String, String) {
    let coll = unique_collection("msys");
    let view = format!("{coll}_view");
    let db = side_client().database(TARGET_DB);
    db.collection(&coll)
        .insert_one(doc! { "k": 1 })
        .await
        .expect("seed");
    db.run_command(doc! { "create": &view, "viewOn": &coll, "pipeline": [] })
        .await
        .expect("create view");
    (coll, view)
}

async fn cleanup(coll: &str, view: &str) {
    let client = side_client();
    drop_collection(&client, view).await;
    drop_collection(&client, coll).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn run_query_refuses_a_data_read_of_a_system_collection() {
    let gateway = boot("readers").await;
    let sql = r#"{"find":"system.views","filter":{}}"#;
    let (body, outcome, audited) = call(
        &gateway,
        "run_query",
        json!({ "server": "mongo", "database": "app", "sql": sql }),
    )
    .await;
    assert_eq!(body["code"], "forbidden_sql", "{body}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("`system.*` collection")),
        "{body}"
    );
    assert_eq!(outcome, "forbidden_sql");
    assert_eq!(audited, sql);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn full_lists_a_system_collection_without_sampling_it() {
    let (coll, view) = seeded().await;
    let gateway = boot("readers").await;
    let (payload, outcome, audited) = call(
        &gateway,
        "describe_schema",
        json!({ "server": "mongo", "database": "app", "table": "system.views",
                "detail": "full" }),
    )
    .await;
    cleanup(&coll, &view).await;

    assert_eq!(outcome, "success", "{payload}");
    assert_eq!(
        audited,
        "app.system.views [detail=full, sampled ≤ 100 docs per collection]"
    );
    assert_eq!(
        payload["collections"][0]["name"], "system.views",
        "{payload}"
    );
    assert_eq!(
        payload["collections"][0]["sample"],
        json!({ "sampled": 0, "fields": [], "truncated": false, "withheld": "system collection" })
    );
}

/// The audited read names the sampling and its per-collection cap, the
/// grant's when tighter; a call that cannot sample records the plain read.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_audit_row_records_document_sampling() {
    let (coll, view) = seeded().await;
    let args = json!({ "server": "mongo", "database": "app", "table": coll, "detail": "full" });
    let (reader, _, reader_sql) =
        call(&boot("readers").await, "describe_schema", args.clone()).await;
    let (capped, _, capped_sql) = call(
        &boot("capped-readers").await,
        "describe_schema",
        args.clone(),
    )
    .await;
    let (metadata, metadata_outcome, metadata_sql) =
        call(&boot("metadata-only").await, "describe_schema", args).await;
    let (_, columns_outcome, columns_sql) = call(
        &boot("readers").await,
        "describe_schema",
        json!({ "server": "mongo", "database": "app", "table": coll }),
    )
    .await;
    cleanup(&coll, &view).await;

    assert_eq!(reader["collections"][0]["sample"]["sampled"], 1, "{reader}");
    assert_eq!(
        reader_sql,
        format!("app.{coll} [detail=full, sampled ≤ 100 docs per collection]")
    );
    assert_eq!(capped["collections"][0]["sample"]["sampled"], 1, "{capped}");
    assert_eq!(
        capped_sql,
        format!("app.{coll} [detail=full, sampled ≤ 5 docs per collection]")
    );
    assert_eq!(metadata_outcome, "success");
    assert!(metadata["note"].is_string(), "{metadata}");
    assert_eq!(metadata_sql, format!("app.{coll}"));
    assert_eq!(columns_outcome, "success");
    assert_eq!(columns_sql, format!("app.{coll}"));
}
