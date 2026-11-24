//! Mongo against `target-mongo`: `describe_schema` v2 (names, full with
//! field inference from a bounded sample, search), a refused command's
//! redacted wording, and a malformed payload's line and column. The HTTP
//! tests assert the audit row each call leaves.

use std::time::Duration;

use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, MongoAdapter, SchemaDetail, SchemaQuery,
};
use mongodb::bson::doc;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mongo_target::{
    TARGET_DB, adapter, drop_collection, side_client, unique_collection,
};

const SERVER: &str = "mongo";

/// A collection named with `-` and `.`, holding two documents of different
/// shapes; one carries a value that must never surface.
async fn seeded(secret: &str) -> String {
    let coll = format!("{}-v2.items", unique_collection("mdesc"));
    side_client()
        .database(TARGET_DB)
        .collection(&coll)
        .insert_many([
            doc! { "email": secret, "address": { "city": "Oslo" }, "age": 41 },
            doc! { "email": mongodb::bson::Bson::Null, "tags": ["a"] },
        ])
        .await
        .expect("seed");
    coll
}

fn schema_query(table: &str, detail: SchemaDetail, sample_limit: u32) -> SchemaQuery<'_> {
    SchemaQuery {
        schema: None,
        table: Some(table),
        search: None,
        detail,
        statement_timeout_ms: None,
        row_limit: 10,
        sample_limit,
        request_id: Uuid::new_v4(),
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn full_infers_fields_from_a_bounded_sample_without_values() {
    let a = adapter(SERVER).await;
    let secret = format!("leak-{}@example.com", Uuid::new_v4().simple());
    let coll = seeded(&secret).await;

    let full = a
        .describe_schema(schema_query(&coll, SchemaDetail::Full, 1))
        .await;
    let names = a
        .describe_schema(schema_query(&coll, SchemaDetail::Names, 0))
        .await;
    let search = |term: &'static str| SchemaQuery {
        table: None,
        search: Some(term),
        ..schema_query(&coll, SchemaDetail::Names, 0)
    };
    let found = a.describe_schema(search("V2.ITEMS")).await;
    let missed = a.describe_schema(search("nope-no-such")).await;
    drop_collection(&side_client(), &coll).await;

    let full = full.expect("full");
    assert_eq!(
        full.columns,
        ["database", "collection", "type", "indexes", "sample"].map(String::from)
    );
    let sample = &full.rows[0][4];
    assert_eq!(
        sample["sampled"], 1,
        "the sample limit is honoured: {sample}"
    );
    let fields: Vec<&str> = sample["fields"]
        .as_array()
        .map(|f| f.iter().filter_map(|f| f["name"].as_str()).collect())
        .unwrap_or_default();
    assert!(fields.contains(&"address.city"), "{fields:?}");
    assert!(!sample.to_string().contains(&secret), "{sample}");

    let names = names.expect("names");
    assert_eq!(names.rows[0].len(), 3, "{:?}", names.rows);
    let found = found.expect("search");
    assert!(
        found.rows.iter().any(|r| r[1] == coll.as_str()),
        "{found:?}"
    );
    assert!(missed.expect("search").rows.is_empty());
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_refused_command_names_the_callers_key_never_a_value() {
    let a = adapter(SERVER).await;
    let secret = format!("leak-{}", Uuid::new_v4().simple());
    let coll = seeded(&secret).await;
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$match":{{"email":"{secret}"}}}},{{"$project":{{"x":{{"$fooo":"$email"}}}}}}],"cursor":{{}}}}"#
    );
    let result = run(&a, &sql).await;
    drop_collection(&side_client(), &coll).await;
    let Err(ExecError::Rejected(rejection)) = result else {
        panic!("expected a rejection, got {result:?}");
    };
    // `168` on older servers, `31325` on newer: both parse-time codes.
    assert!(
        ["168", "31325"].contains(&rejection.sqlstate()),
        "{rejection:?}"
    );
    assert_eq!(
        rejection.message(),
        "unrecognized expression operator: $fooo"
    );
    assert!(!rejection.to_string().contains(&secret));
}

async fn run(a: &MongoAdapter, sql: &str) -> Result<db_mcp_gateway::exec::ExecResult, ExecError> {
    a.execute(ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 10,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    })
    .await
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_malformed_payload_says_where_it_broke() {
    let a = adapter(SERVER).await;
    let err = run(&a, "{\"find\": \"users\",\n \"filter\": {\"ssn\": 'x'}}")
        .await
        .expect_err("not JSON");
    let ExecError::Forbidden(reason) = err else {
        panic!("expected the rejector's refusal, got {err:?}");
    };
    assert_eq!(
        reason,
        "mongo command is not valid JSON at line 2, column 20"
    );
}

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
  - group: metadata-only
    grants:
      - { server: mongo, database: app, action: schema_read }
"#;

async fn boot(group: &str) -> LoggedInGateway {
    let user = MockUser {
        sub: format!("mdesc-{}", Uuid::new_v4().simple()),
        email: "mongo-describe@example.com".to_string(),
        groups: vec![group.to_string()],
    };
    spawn_logged_in(YAML, user).await
}

async fn describe_full(gateway: &LoggedInGateway, coll: &str) -> Value {
    let response: Value = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
        .post(format!("{}/mcp", gateway.url))
        .bearer_auth(&gateway.bearer)
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "describe_schema", "arguments": {
                "server": "mongo", "database": "app", "table": coll, "detail": "full" } }
        }))
        .send()
        .await
        .expect("gateway answers")
        .json()
        .await
        .expect("JSON-RPC body");
    assert_eq!(response["result"]["isError"], false, "{response}");
    let row = latest_audit(
        &gateway.state_db,
        &gateway.user_sub,
        "describe_schema",
        "full",
    )
    .await;
    assert_eq!(row.outcome, "success");
    let plain = format!("app.{coll}");
    let sql = row.sql.as_deref().unwrap_or_default();
    assert!(
        sql == plain || sql == format!("{plain} [detail=full, sampled ≤ 100 docs per collection]"),
        "{sql}"
    );
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    serde_json::from_str(text).expect("JSON payload")
}

/// `full` samples documents under `query_read`; a `schema_read`-only caller
/// gets the collections without fields, and is told why.
#[tokio::test]
#[serial_test::parallel(world)]
async fn full_over_http_samples_only_under_query_read() {
    let secret = format!("leak-{}", Uuid::new_v4().simple());
    let coll = seeded(&secret).await;
    let reader = describe_full(&boot("readers").await, &coll).await;
    let metadata = describe_full(&boot("metadata-only").await, &coll).await;
    drop_collection(&side_client(), &coll).await;

    let sample = &reader["collections"][0]["sample"];
    assert_eq!(sample["sampled"], 2, "{reader}");
    assert!(!reader.to_string().contains(&secret));
    assert!(reader.get("note").is_none(), "{reader}");

    assert!(
        metadata["collections"][0].get("sample").is_none(),
        "{metadata}"
    );
    assert!(metadata["collections"][0]["indexes"].is_array());
    assert!(metadata["note"].is_string(), "{metadata}");
}

/// Field types are the stored BSON element types: a subdocument shaped
/// exactly like an ObjectId's extended JSON is an `object` holding a
/// `string`, a real ObjectId an `objectId`, an Int64 a `long`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn sampled_types_are_bson_types_not_extended_json_shapes() {
    let a = adapter(SERVER).await;
    let coll = format!("{}-types", unique_collection("mdesc"));
    let hex = "65f0c0ffee0000000000abcd";
    side_client()
        .database(TARGET_DB)
        .collection(&coll)
        .insert_one(doc! {
            "mimic": { "$oid": hex },
            "real": mongodb::bson::oid::ObjectId::parse_str(hex).expect("hex"),
            "when": mongodb::bson::DateTime::from_millis(0),
            "big": 5_i64,
            "small": 5_i32,
            "bytes": mongodb::bson::Binary {
                subtype: mongodb::bson::spec::BinarySubtype::Generic,
                bytes: vec![1],
            },
        })
        .await
        .expect("seed");

    let full = a
        .describe_schema(schema_query(&coll, SchemaDetail::Full, 5))
        .await;
    drop_collection(&side_client(), &coll).await;

    let full = full.expect("full");
    let sample = &full.rows[0][4];
    let types = |name: &str| {
        sample["fields"]
            .as_array()
            .and_then(|fields| fields.iter().find(|f| f["name"] == name))
            .map(|f| f["types"].clone())
            .unwrap_or(Value::Null)
    };
    assert_eq!(types("mimic"), json!(["object"]), "{sample}");
    assert_eq!(types("mimic.$oid"), json!(["string"]), "{sample}");
    assert_eq!(types("real"), json!(["objectId"]), "{sample}");
    assert_eq!(types("_id"), json!(["objectId"]), "{sample}");
    assert_eq!(types("when"), json!(["date"]), "{sample}");
    assert_eq!(types("big"), json!(["long"]), "{sample}");
    assert_eq!(types("small"), json!(["int"]), "{sample}");
    assert_eq!(types("bytes"), json!(["binary"]), "{sample}");
    assert!(!sample.to_string().contains(hex), "{sample}");
}

/// The `sample` of a collection holding exactly `document`.
async fn sample_of(document: mongodb::bson::Document) -> Value {
    let a = adapter(SERVER).await;
    let coll = format!("{}-wide", unique_collection("mdesc"));
    side_client()
        .database(TARGET_DB)
        .collection(&coll)
        .insert_one(document)
        .await
        .expect("seed");
    let full = a
        .describe_schema(schema_query(&coll, SchemaDetail::Full, 5))
        .await;
    drop_collection(&side_client(), &coll).await;
    full.expect("full").rows.remove(0).remove(4)
}

fn field_names(sample: &Value) -> Vec<&str> {
    sample["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect()
}

/// A hundred fields at each of three levels: a million leaves in a document
/// well under 16 MiB, whose names alone would not fit one as metadata. The
/// sample is cut and says so; the listing stands.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_wide_and_deep_document_is_a_truncated_sample_not_an_error() {
    let level = |child: mongodb::bson::Bson| -> mongodb::bson::Document {
        (0..100)
            .map(|i| (format!("{i:02}"), child.clone()))
            .collect()
    };
    let leaves = level(mongodb::bson::Bson::Int32(1));
    let sample = sample_of(level(level(leaves.into()).into())).await;
    assert_eq!(sample["sampled"], 1, "{sample}");
    assert_eq!(sample["truncated"], true);
    let names = field_names(&sample);
    assert_eq!(names.len(), 200);
    assert!(names.contains(&"00"), "{names:?}");
    assert!(names.contains(&"00.00"), "{names:?}");
}

/// The bound holds on every level: a nested field past it is not reported
/// even when it sorts first by name, and the sample says it was cut.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_document_past_the_field_bound_below_the_top_level_is_truncated() {
    let mut many: mongodb::bson::Document = (0..250)
        .map(|i| (format!("f{i:03}"), mongodb::bson::Bson::Int32(1)))
        .collect();
    many.insert("a_late", 1);
    let sample = sample_of(doc! { "a": { "b": many } }).await;
    assert_eq!(sample["truncated"], true);
    let names = field_names(&sample);
    assert!(names.contains(&"a.b.f000"), "{names:?}");
    assert!(!names.contains(&"a.b.a_late"), "{names:?}");
}

/// The server reads 201 fields of an object and no more: a later field is
/// not reported even when it sorts first by name, and the sample says it
/// was cut.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_field_past_the_per_document_bound_is_not_read() {
    let mut document: mongodb::bson::Document = (0..210)
        .map(|i| (format!("f{i:03}"), mongodb::bson::Bson::Int32(1)))
        .collect();
    document.insert("a_late", 1);
    let sample = sample_of(document).await;
    assert_eq!(sample["truncated"], true);
    let names = field_names(&sample);
    assert!(!names.contains(&"a_late"), "{names:?}");
    assert!(names.contains(&"f000"), "{names:?}");
}

/// A field name past the reported length is left out, and the sample says
/// so: names alone must not outgrow a reply either.
#[tokio::test]
#[serial_test::parallel(world)]
async fn an_oversized_field_name_is_left_out_and_reported() {
    let long = "n".repeat(2_000);
    let sample = sample_of(doc! { long.as_str(): { "child": 1 }, "kept": 1 }).await;
    assert_eq!(field_names(&sample), ["_id", "kept"]);
    assert_eq!(sample["truncated"], true);
}
