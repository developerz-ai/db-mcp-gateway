//! Real-mongo integration tests for `MongoAdapter::execute` (#58).
//!
//! Targets the `target-mongo` service from `docker-compose.dev.yml`
//! (mongo:7 on localhost:27018). Covers the four allowed commands
//! (`find` / `aggregate` / `count` / `distinct`), the `maxTimeMS`
//! timeout path, and rejector-denied write commands.
//!
//! The cancellation drop-guard contract lives in
//! `audit_dispatch_cancellation_real_db.rs` — it needs the state DB,
//! not the target.

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{DbAdapter, ExecError, ExecQuery, MongoAdapter};

const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 27018;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";

fn server() -> Server {
    Server {
        name: "mongo".to_string(),
        kind: ServerKind::Mongo,
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
        password: Password::Literal(TARGET_PASSWORD.into()),
        description: String::new(),
        // The dev container's root user lives in `admin` — see
        // docker-compose.dev.yml `target-mongo`. Production deployments
        // typically create a per-db least-privilege user and leave this
        // `None` (defaults to `name`).
        auth_database: Some("admin".to_string()),
    }
}

async fn adapter() -> MongoAdapter {
    MongoAdapter::open(&server(), &database())
        .await
        .expect("target-mongo reachable; run `bin/dev up`")
}

fn unique_collection() -> String {
    format!("mongoexec_{}", uuid::Uuid::new_v4().simple())
}

async fn seed(a: &MongoAdapter, collection: &str, count: usize) {
    let docs: Vec<String> = (1..=count)
        .map(|i| {
            format!(
                r#"{{"i":{i},"role":"{role}"}}"#,
                role = if i % 2 == 0 { "admin" } else { "user" }
            )
        })
        .collect();
    let docs_json = docs.join(",");
    let insert = format!(r#"{{"insert":"{collection}","documents":[{docs_json}]}}"#,);
    // We can't go through the adapter — the rejector blocks `insert`.
    // Use the raw mongo client via a fresh side adapter for setup. The
    // production path NEVER seeds; this is test-only.
    use mongodb::Client;
    use mongodb::bson::Document;
    use mongodb::options::{ClientOptions, Credential, ServerAddress};
    let credential = Credential::builder()
        .username(TARGET_USER.to_string())
        .password(TARGET_PASSWORD.to_string())
        .source(Some("admin".to_string()))
        .build();
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: TARGET_HOST.to_string(),
            port: Some(TARGET_PORT),
        }])
        .credential(credential)
        .default_database(TARGET_DB.to_string())
        .build();
    let client = Client::with_options(options).expect("seed client");
    let doc: Document = serde_json::from_str(&insert).expect("seed doc parses");
    client
        .database(TARGET_DB)
        .run_command(doc)
        .await
        .expect("seed insert");
    // Hint: silence the unused-binding compile warning when count == 0
    let _ = a;
}

async fn drop_collection(collection: &str) {
    let client = side_client();
    let _ = client
        .database(TARGET_DB)
        .run_command(mongodb::bson::doc! { "drop": collection })
        .await;
}

/// `listCollections` filtered by exact name — returns true iff mongo
/// has that collection in `TARGET_DB`. Used by the rejector test to
/// pin "the write never reached mongo" with server-side evidence, not
/// just the gateway's error type.
async fn collection_exists(collection: &str) -> bool {
    use futures::StreamExt;
    use mongodb::bson::doc;
    let client = side_client();
    let mut cursor = client
        .database(TARGET_DB)
        .run_cursor_command(doc! {
            "listCollections": 1,
            "filter": { "name": collection },
            "nameOnly": true,
        })
        .await
        .expect("listCollections runs");
    cursor.next().await.is_some()
}

/// Side-channel client for test setup/teardown — bypasses the rejector
/// so we can seed, drop, and inspect collections. NEVER use this path
/// in production code: it has root-equivalent access.
fn side_client() -> mongodb::Client {
    use mongodb::Client;
    use mongodb::options::{ClientOptions, Credential, ServerAddress};
    let credential = Credential::builder()
        .username(TARGET_USER.to_string())
        .password(TARGET_PASSWORD.to_string())
        .source(Some("admin".to_string()))
        .build();
    let options = ClientOptions::builder()
        .hosts(vec![ServerAddress::Tcp {
            host: TARGET_HOST.to_string(),
            port: Some(TARGET_PORT),
        }])
        .credential(credential)
        .default_database(TARGET_DB.to_string())
        .build();
    Client::with_options(options).expect("side client builds")
}

/// `find` returns documents row-by-row in the `[document]` shape the
/// MCP layer expects. Each row carries the matched doc as a JSON value
/// under the `"document"` column.
#[tokio::test]
async fn find_returns_documents_under_document_column() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&a, &coll, 5).await;

    let sql = format!(r#"{{"find":"{coll}","filter":{{"role":"admin"}}}}"#);
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 100,
        })
        .await
        .expect("find runs");

    drop_collection(&coll).await;

    assert_eq!(result.columns, vec!["document".to_string()]);
    // 2 admins in the 1..=5 seed (i=2, i=4).
    assert_eq!(result.rows.len(), 2);
    assert!(!result.truncated);

    // Each row is `[document_as_json]`; the document has the seeded fields.
    for row in &result.rows {
        assert_eq!(row.len(), 1);
        let doc = &row[0];
        assert!(doc.is_object(), "row must be a JSON object: {doc}");
        assert_eq!(doc["role"].as_str(), Some("admin"));
        // `i` is one of {2, 4}; can't be more specific without ordering.
        assert!(doc["i"].is_number());
    }
}

/// `row_limit` truncates the result set and flags `truncated = true`.
/// The cursor stops draining mid-stream; mongo's getMore loop never
/// pulls the over-budget batch.
#[tokio::test]
async fn find_respects_row_limit_with_truncation_flag() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&a, &coll, 20).await;

    let sql = format!(r#"{{"find":"{coll}","filter":{{}}}}"#);
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 5,
        })
        .await
        .expect("find runs");

    drop_collection(&coll).await;

    assert_eq!(result.rows.len(), 5);
    assert!(result.truncated, "expected truncated=true beyond row_limit");
}

/// `aggregate` returns each stage's output doc in the same `[document]`
/// shape as `find`. The $group stage proves pipeline execution actually
/// runs server-side (not a pass-through of the input).
#[tokio::test]
async fn aggregate_runs_pipeline_and_returns_groups() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&a, &coll, 6).await; // 3 admin + 3 user

    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$group":{{"_id":"$role","n":{{"$sum":1}}}}}}],"cursor":{{}}}}"#,
    );
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 100,
        })
        .await
        .expect("aggregate runs");

    drop_collection(&coll).await;

    assert_eq!(result.columns, vec!["document".to_string()]);
    assert_eq!(result.rows.len(), 2);
    // Each row is a `_id: <role>, n: 3` shape.
    let totals: std::collections::HashMap<String, i64> = result
        .rows
        .iter()
        .map(|r| {
            let d = &r[0];
            let id = d["_id"].as_str().unwrap().to_string();
            let n = d["n"].as_i64().unwrap();
            (id, n)
        })
        .collect();
    assert_eq!(totals.get("admin").copied(), Some(3));
    assert_eq!(totals.get("user").copied(), Some(3));
}

/// `count` returns a single row, single column under `"count"`. The
/// response's `n` field is what mongo's wire protocol carries on the
/// `count` command's reply.
#[tokio::test]
async fn count_returns_scalar_under_count_column() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&a, &coll, 7).await;

    let sql = format!(r#"{{"count":"{coll}","query":{{}}}}"#);
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 100,
        })
        .await
        .expect("count runs");

    drop_collection(&coll).await;

    assert_eq!(result.columns, vec!["count".to_string()]);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0][0].as_i64(), Some(7));
    assert!(!result.truncated);
}

/// `distinct` returns one row per unique value. Two distinct roles in
/// the seed → two rows.
#[tokio::test]
async fn distinct_returns_unique_values_one_per_row() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&a, &coll, 4).await; // 2 admin + 2 user → 2 distinct roles

    let sql = format!(r#"{{"distinct":"{coll}","key":"role"}}"#);
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 100,
        })
        .await
        .expect("distinct runs");

    drop_collection(&coll).await;

    assert_eq!(result.columns, vec!["value".to_string()]);
    let values: std::collections::HashSet<&str> =
        result.rows.iter().filter_map(|r| r[0].as_str()).collect();
    assert_eq!(values.len(), 2);
    assert!(values.contains("admin"));
    assert!(values.contains("user"));
}

/// `maxTimeMS` injection: a slow aggregate pipeline that sleeps past
/// the budget surfaces as a typed `ExecError::Timeout`. The sleep is
/// implemented via `$function` — oh wait, the rejector blocks `$function`.
/// Use `$lookup`'s pipeline with a `$facet` that returns a huge generated
/// document instead, and a tiny budget. Mongo's `maxTimeMS` catches it.
///
/// Actually the simplest cross-version-safe slow stage: `$collStats` with
/// a tiny `maxTimeMS`. Use a `$sample` size that has to scan the whole
/// collection. Either way the test pins the typed mapping.
#[tokio::test]
async fn max_time_ms_surfaces_as_typed_timeout() {
    let a = adapter().await;
    let coll = unique_collection();
    // 5k docs so the aggregate has actual work to do under a microsecond
    // budget. We use $sortByCount + $sample which is cheap to set up but
    // takes more than 1ms on a fresh collection.
    seed(&a, &coll, 5000).await;

    // 1ms budget. mongo can't possibly drain 5000 docs through a sort
    // pipeline in 1ms; the server kills it with code 50 (MaxTimeMSExpired).
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$sort":{{"i":1}}}},{{"$group":{{"_id":"$role","ns":{{"$push":"$i"}}}}}}],"cursor":{{}}}}"#,
    );

    // Bounded-retry strict: a single run on a fast box can squeak past the
    // 1ms budget before mongo notices. Five back-to-back runs against a
    // 5k-doc sort+group pipeline shouldn't all win — if none of them trips
    // `MaxTimeMSExpired`, the typed-mapping contract is unverified and we
    // fail the test. That's the regression we care about; the old `Ok(_)`
    // arm let the assertion no-op.
    let mut saw_timeout = false;
    let mut last_other: Option<ExecError> = None;
    for _ in 0..5 {
        let result = a
            .execute(ExecQuery {
                sql: &sql,
                binds: &[],
                statement_timeout_ms: Some(1),
                row_limit: 10000,
            })
            .await;
        match result {
            Err(ExecError::Timeout) => {
                saw_timeout = true;
                break;
            }
            Err(other) => {
                last_other = Some(other);
                break;
            }
            Ok(_) => {}
        }
    }

    drop_collection(&coll).await;

    if let Some(other) = last_other {
        panic!("expected Timeout or transient success, got {other:?}");
    }
    assert!(
        saw_timeout,
        "expected ExecError::Timeout within 5 attempts; mongo never tripped MaxTimeMSExpired"
    );
}

/// Rejected write commands surface as `ExecError::Forbidden`, NOT
/// `ExecError::Sql`. The mongo wire layer never sees them — the rejector
/// stops them in the gateway. Pins the contract claudetm shipped in #57's
/// follow-up commit.
#[tokio::test]
async fn rejected_write_command_does_not_reach_mongo() {
    let a = adapter().await;
    let coll = unique_collection();
    let sql = format!(r#"{{"insert":"{coll}","documents":[{{"x":1}}]}}"#);
    let err = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 10,
        })
        .await
        .expect_err("insert is denied by the rejector");
    assert!(matches!(err, ExecError::Forbidden(_)), "got {err:?}");

    // Prove the "never reached mongo" half of the contract: the
    // collection mongo would have auto-created on a successful insert
    // doesn't exist server-side. Without this, the test only checks
    // the gateway's error mapping — a regression that *did* forward
    // the insert but happened to also error out could still pass.
    assert!(
        !collection_exists(&coll).await,
        "rejector let `{coll}` reach mongo: collection was created"
    );
}

/// `auth_database: None` means "use `database.name` as the auth source"
/// (spec 12 §"least-privilege per-db user"). The dev container's root
/// user lives in `admin` — not `app` — so falling back to "app" produces
/// an authentication failure on the first wire-level operation. Any
/// error here is fine; what matters is that a successful query is
/// impossible, which is only true when the override field is honored on
/// construction. Pins the public-behavior contract CodeRabbit flagged.
///
/// The `Some(...)` override path is exercised by every other test in
/// this file — `adapter()` builds `Database { auth_database:
/// Some("admin"), .. }` and queries against `app` succeed. Together the
/// two arms pin both branches end-to-end.
#[tokio::test]
async fn auth_database_none_falls_back_to_database_name() {
    let mut db = database();
    db.auth_database = None;
    let s = server();
    let a = MongoAdapter::open(&s, &db).await.expect("client builds");

    let sql = r#"{"count":"missing","query":{}}"#;
    let result = a
        .execute(ExecQuery {
            sql,
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 10,
        })
        .await;
    assert!(
        result.is_err(),
        "expected auth failure when fallback points at user-less `app`; got {result:?}"
    );
}
