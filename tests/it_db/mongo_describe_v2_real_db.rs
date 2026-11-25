//! Mongo against `target-mongo`: `describe_schema` v2 (names, full with
//! field inference from a bounded sample, search), a refused command's
//! redacted wording, and a malformed payload's line and column. The HTTP
//! tests assert the audit row each call leaves.

use std::time::Duration;

use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::{Database, Server};
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, MongoAdapter, PoolSizing, SchemaDetail, SchemaQuery,
};
use mongodb::bson::{Document, RawDocumentBuf, doc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::common::audit::latest_audit;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::mongo_target::{
    TARGET_DB, adapter, database, server, side_client, unique_collection,
};

const SERVER: &str = "mongo";

/// A collection or a database of a test's own, dropped when the test ends,
/// by a panic too. Made before anything is seeded into it.
struct Scratch {
    name: String,
    database: String,
    drop_command: Document,
}

impl Scratch {
    /// A uniquely named collection of the shared target database.
    fn collection(suffix: &str) -> Self {
        let name = format!("{}{suffix}", unique_collection("mdesc"));
        Self {
            database: TARGET_DB.to_string(),
            drop_command: doc! { "drop": &name },
            name,
        }
    }

    /// A uniquely named database.
    fn database() -> Self {
        let id = Uuid::new_v4().simple().to_string();
        let name = format!("mdesc_{}", &id[..12]);
        Self {
            database: name.clone(),
            drop_command: doc! { "dropDatabase": 1 },
            name,
        }
    }

    async fn insert(&self, documents: Vec<RawDocumentBuf>) {
        for document in documents {
            side_client()
                .database(&self.database)
                .collection::<RawDocumentBuf>(&self.name)
                .insert_one(document)
                .await
                .expect("seed");
        }
    }
}

impl Drop for Scratch {
    /// On a runtime of its own thread: the test's may be unwinding.
    fn drop(&mut self) {
        let (database, command) = (self.database.clone(), self.drop_command.clone());
        let dropped = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map(|runtime| {
                    runtime.block_on(async {
                        side_client().database(&database).run_command(command).await
                    })
                })
        })
        .join();
        if !matches!(dropped, Ok(Ok(Ok(_)))) {
            eprintln!("left behind: {} in {}", self.name, self.database);
        }
    }
}

fn raw(document: &Document) -> RawDocumentBuf {
    RawDocumentBuf::try_from(document).expect("encodes")
}

/// A test that panics after seeding leaves nothing on the shared target.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_panicking_test_drops_its_scratch() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let panicked = tokio::spawn(async move {
        let scratch = Scratch::collection("-panic");
        scratch.insert(vec![raw(&doc! { "a": 1 })]).await;
        tx.send(scratch.name.clone()).expect("receiver waits");
        panic!("on purpose");
    })
    .await;
    assert!(panicked.is_err_and(|err| err.is_panic()));
    let name = rx.await.expect("seeded");
    let left = side_client()
        .database(TARGET_DB)
        .list_collection_names()
        .filter(doc! { "name": &name })
        .await
        .expect("lists");
    assert!(left.is_empty(), "{left:?}");
}

/// A collection named with `-` and `.`, holding two documents of different
/// shapes; one carries a value that must never surface.
async fn seeded(secret: &str) -> Scratch {
    let scratch = Scratch::collection("-v2.items");
    scratch
        .insert(vec![
            raw(&doc! { "email": secret, "address": { "city": "Oslo" }, "age": 41 }),
            raw(&doc! { "email": mongodb::bson::Bson::Null, "tags": ["a"] }),
        ])
        .await;
    scratch
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
    let scratch = seeded(&secret).await;
    let coll = scratch.name.as_str();

    let full = a
        .describe_schema(schema_query(coll, SchemaDetail::Full, 1))
        .await;
    let names = a
        .describe_schema(schema_query(coll, SchemaDetail::Names, 0))
        .await;
    let search = |term: &'static str| SchemaQuery {
        table: None,
        search: Some(term),
        ..schema_query(coll, SchemaDetail::Names, 0)
    };
    let found = a.describe_schema(search("V2.ITEMS")).await;
    let missed = a.describe_schema(search("nope-no-such")).await;

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
    assert!(found.rows.iter().any(|r| r[1] == coll), "{found:?}");
    assert!(missed.expect("search").rows.is_empty());
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_refused_command_names_the_callers_key_never_a_value() {
    let a = adapter(SERVER).await;
    let secret = format!("leak-{}", Uuid::new_v4().simple());
    let scratch = seeded(&secret).await;
    let coll = scratch.name.as_str();
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$match":{{"email":"{secret}"}}}},{{"$project":{{"x":{{"$fooo":"$email"}}}}}}],"cursor":{{}}}}"#
    );
    let result = run(&a, &sql).await;
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
    let scratch = seeded(&secret).await;
    let coll = scratch.name.as_str();
    let reader = describe_full(&boot("readers").await, coll).await;
    let metadata = describe_full(&boot("metadata-only").await, coll).await;

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
    let scratch = Scratch::collection("-types");
    let coll = scratch.name.as_str();
    let hex = "65f0c0ffee0000000000abcd";
    scratch
        .insert(vec![raw(&doc! {
            "mimic": { "$oid": hex },
            "real": mongodb::bson::oid::ObjectId::parse_str(hex).expect("hex"),
            "when": mongodb::bson::DateTime::from_millis(0),
            "big": 5_i64,
            "small": 5_i32,
            "bytes": mongodb::bson::Binary {
                subtype: mongodb::bson::spec::BinarySubtype::Generic,
                bytes: vec![1],
            },
        })])
        .await;

    let full = a
        .describe_schema(schema_query(coll, SchemaDetail::Full, 5))
        .await;

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

/// The `sample` of a collection holding exactly `documents`.
async fn sample_of_all(documents: Vec<RawDocumentBuf>) -> Value {
    let a = adapter(SERVER).await;
    let scratch = Scratch::collection("-sample");
    scratch.insert(documents).await;
    let full = a
        .describe_schema(schema_query(&scratch.name, SchemaDetail::Full, 5))
        .await;
    full.expect("full").rows.remove(0).remove(4)
}

async fn sample_of(document: Document) -> Value {
    sample_of_all(vec![raw(&document)]).await
}

fn field<'a>(sample: &'a Value, name: &str) -> &'a Value {
    sample["fields"]
        .as_array()
        .and_then(|fields| fields.iter().find(|f| f["name"] == name))
        .unwrap_or(&Value::Null)
}

/// One document spells a path in several ways — a subdocument's field and a
/// literal dotted name, at any level: it counts once, and every type it
/// held there is kept. `count` is documents, so it never passes `sampled`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_document_counts_once_for_a_path_it_spells_twice() {
    let sample = sample_of_all(vec![
        raw(&doc! {
            "mimic": { "$oid": "65f0c0ffee0000000000abcd" },
            "mimic.$oid": 7,
            "a": { "b.c": 1, "b": { "c": "x" } },
            "a.b": { "c": 1.5 },
            "list": [{ "x": 1 }, { "x": "y" }],
            "": { "x": 1 },
            "x": true,
        }),
        raw(&doc! { "mimic.$oid": "s" }),
    ])
    .await;
    let is = |name: &str, types: Value, count: u32| {
        assert_eq!(
            field(&sample, name),
            &json!({ "name": name, "types": types, "count": count }),
            "{sample}"
        );
    };
    is("mimic.$oid", json!(["string", "int"]), 2);
    is("a.b.c", json!(["int", "string", "double"]), 1);
    is("a.b", json!(["object"]), 1);
    // An array's items are not walked.
    is("list", json!(["array"]), 1);
    assert_eq!(field(&sample, "list.x"), &Value::Null, "{sample}");
    // An empty name is a name: its child is not a top-level field.
    is("", json!(["object"]), 1);
    is(".x", json!(["int"]), 1);
    is("x", json!(["bool"]), 1);
    assert_eq!(sample["truncated"], false);
}

/// BSON allows a name twice in one document; it is one document's field.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_name_stored_twice_counts_once() {
    let dup = |element: &[u8]| [element, b"dup\0"].concat();
    let body = [
        dup(&[0x10]),
        vec![1, 0, 0, 0],
        dup(&[0x0A]),
        dup(&[0x08]),
        vec![1],
    ]
    .concat();
    let document = RawDocumentBuf::from_bytes(framed(&body)).expect("valid BSON");
    let sample = sample_of_all(vec![document]).await;
    assert_eq!(
        field(&sample, "dup"),
        &json!({ "name": "dup", "types": ["int", "null", "bool"], "count": 1 }),
        "{sample}"
    );
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
    let level = |child: mongodb::bson::Bson| -> Document {
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
    let mut many: Document = (0..250)
        .map(|i| (format!("f{i:03}"), mongodb::bson::Bson::Int32(1)))
        .collect();
    many.insert("a_late", 1);
    let sample = sample_of(doc! { "a": { "b": many } }).await;
    assert_eq!(sample["truncated"], true);
    let names = field_names(&sample);
    assert!(names.contains(&"a.b.f000"), "{names:?}");
    assert!(!names.contains(&"a.b.a_late"), "{names:?}");
}

/// The gateway reads 201 fields of an object and no more: a later field is
/// not reported even when it sorts first by name, and the sample says it
/// was cut.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_field_past_the_per_document_bound_is_not_read() {
    let mut document: Document = (0..210)
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

/// The bytes of a BSON document of `body`'s elements.
fn framed(body: &[u8]) -> Vec<u8> {
    let len = i32::try_from(body.len() + 5).expect("fits");
    [&len.to_le_bytes()[..], body, &[0]].concat()
}

/// A document close to 16 MiB of nothing but short distinct field names
/// (each a `null`), held under `parents`.
fn widest_document(parents: &[&str]) -> RawDocumentBuf {
    const NAME: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut body = Vec::new();
    for i in 0..2_600_000_usize {
        let mut rest = i;
        body.push(0x0A);
        for _ in 0..4 {
            body.push(NAME[rest % NAME.len()]);
            rest /= NAME.len();
        }
        body.push(0);
    }
    for parent in parents.iter().rev() {
        let child = framed(&body);
        body = [&[0x03][..], parent.as_bytes(), &[0], &child].concat();
    }
    RawDocumentBuf::from_bytes(framed(&body)).expect("valid BSON")
}

/// An adapter on `name`, a database of the target.
async fn adapter_of(name: &str) -> MongoAdapter {
    let database = Database {
        name: name.to_string(),
        ..database()
    };
    let server = Server {
        databases: vec![database.clone()],
        ..server(SERVER)
    };
    MongoAdapter::open(
        &server,
        &database,
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("target-mongo reachable; run `bin/dev up`")
}

/// The widest legal object at each reported level: the sample is cut and
/// says so, and the other collections of the same call are still listed.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_widest_object_at_any_level_is_a_truncated_sample() {
    let mut wrong = Vec::new();
    for parents in [&[][..], &["w"], &["w", "x"]] {
        // A database of its own: the listing is capped, so another test's
        // collections could push these two out of it.
        let scratch = Scratch::database();
        let (a, db) = (
            adapter_of(&scratch.name).await,
            side_client().database(&scratch.name),
        );
        let (wide, plain) = ("wide", "plain");
        db.collection::<RawDocumentBuf>(wide)
            .insert_one(widest_document(parents))
            .await
            .expect("seed wide");
        db.collection::<Document>(plain)
            .insert_one(doc! { "field": 1 })
            .await
            .expect("seed plain");
        let full = a
            .describe_schema(SchemaQuery {
                table: None,
                ..schema_query(plain, SchemaDetail::Full, 5)
            })
            .await;

        let depth = parents.len() + 1;
        let full = match full {
            Ok(full) => full,
            Err(err) => {
                wrong.push(format!("level {depth}: {err:?}"));
                continue;
            }
        };
        let sample_of = |name: &str| {
            full.rows
                .iter()
                .find(|row| row[1] == name)
                .map(|row| row[4].clone())
                .unwrap_or_default()
        };
        let (wide, plain) = (sample_of(wide), sample_of(plain));
        let first = [parents, &["0000"]].concat().join(".");
        if wide["sampled"] != 1
            || wide["truncated"] != true
            || !field_names(&wide).contains(&first.as_str())
        {
            wrong.push(format!("level {depth}: {wide}"));
        }
        if plain["truncated"] != false || field_names(&plain) != ["_id", "field"] {
            wrong.push(format!("level {depth}, the other collection: {plain}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The documents read for a sample are held to the 32 MiB result budget in
/// their stored form, however little is reported of them.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_sample_past_the_byte_budget_is_cut_and_says_so() {
    let blob = raw(&doc! { "blob": "x".repeat(12 * 1024 * 1024) });
    let sample = sample_of_all(vec![blob; 3]).await;
    assert_eq!(sample["sampled"], 2, "{sample}");
    assert_eq!(sample["truncated"], true);
    assert_eq!(field_names(&sample), ["_id", "blob"]);
}
