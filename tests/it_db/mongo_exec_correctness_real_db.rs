//! Real-mongo tests for what the adapter answers, not just that it answers:
//! non-finite doubles render as Extended JSON (never a fabricated `null`), a
//! role missing a privilege is a permission refusal (never a syntax error),
//! and a saturated pool is `unavailable` (never the caller's `timeout`).
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use std::time::{Duration, Instant};

use mongodb::bson::{Document, doc};
use serde_json::json;
use uuid::Uuid;

use crate::common::mongo_target::{
    TARGET_DB, adapter, database, drop_collection, server, side_client, unique_collection,
};
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::config::Password;
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, ExecResult, MongoAdapter, PoolSizing,
};

async fn run(
    a: &MongoAdapter,
    sql: &str,
    statement_timeout_ms: Option<u32>,
) -> Result<ExecResult, ExecError> {
    a.execute(ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms,
        row_limit: 100,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    })
    .await
}

async fn insert(collection: &str, documents: Vec<Document>) {
    side_client()
        .database(TARGET_DB)
        .run_command(doc! { "insert": collection, "documents": documents })
        .await
        .expect("seed insert");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn non_finite_doubles_render_as_extended_json() {
    let a = adapter("mongo").await;
    let coll = unique_collection("mongodbl");
    insert(
        &coll,
        vec![doc! {
            "_id": 1,
            "nan": f64::NAN,
            "inf": f64::INFINITY,
            "ninf": f64::NEG_INFINITY,
            "nested": [f64::NAN, 2.5],
            "nothing": null,
        }],
    )
    .await;

    let find = run(&a, &format!(r#"{{"find":"{coll}"}}"#), None).await;
    let distinct = run(&a, &format!(r#"{{"distinct":"{coll}","key":"inf"}}"#), None).await;
    drop_collection(&side_client(), &coll).await;

    let find = find.expect("find");
    assert_eq!(
        find.rows,
        vec![vec![json!({
            "_id": 1,
            "nan": { "$numberDouble": "NaN" },
            "inf": { "$numberDouble": "Infinity" },
            "ninf": { "$numberDouble": "-Infinity" },
            "nested": [{ "$numberDouble": "NaN" }, 2.5],
            "nothing": null,
        })]]
    );
    assert_eq!(
        distinct.expect("distinct").rows,
        vec![vec![json!({ "$numberDouble": "Infinity" })]]
    );
}

/// A user whose role may `find` on `allowed` only, in [`TARGET_DB`].
struct NarrowUser {
    user: String,
    role: String,
}

impl NarrowUser {
    const PASSWORD: &str = "narrow-dev-only";

    async fn create(allowed: &str) -> Self {
        let suffix = Uuid::new_v4().simple().to_string();
        let (user, role) = (format!("gw_narrow_{suffix}"), format!("gw_find_{suffix}"));
        let db = side_client().database(TARGET_DB);
        db.run_command(doc! {
            "createRole": &role,
            "privileges": [{ "resource": { "db": TARGET_DB, "collection": allowed }, "actions": ["find"] }],
            "roles": [],
        })
        .await
        .expect("createRole");
        db.run_command(doc! { "createUser": &user, "pwd": Self::PASSWORD, "roles": [&role] })
            .await
            .expect("createUser");
        Self { user, role }
    }

    async fn drop(self) {
        let db = side_client().database(TARGET_DB);
        let _ = db.run_command(doc! { "dropUser": &self.user }).await;
        let _ = db.run_command(doc! { "dropRole": &self.role }).await;
    }
}

/// Mongo's `Unauthorized` (code 13) is the role lacking a privilege — the
/// agent's query is fine. It carries the code and the gateway's wording,
/// never the server's message (which echoes the command).
#[tokio::test]
#[serial_test::parallel(world)]
async fn unauthorized_is_a_permission_refusal_not_a_syntax_error() {
    let allowed = unique_collection("mongoauthz");
    let denied = unique_collection("mongoauthz");
    let narrow = NarrowUser::create(&allowed).await;
    let mut db = database();
    db.role = narrow.user.clone();
    db.password = Password::Literal(NarrowUser::PASSWORD.into());
    db.auth_database = None;
    let a = MongoAdapter::open(
        &server("mongo"),
        &db,
        PoolSizing::default(),
        DetachedTasks::new(),
    )
    .await
    .expect("client builds");

    let ok = run(&a, &format!(r#"{{"find":"{allowed}"}}"#), None).await;
    let refused = run(
        &a,
        &format!(r#"{{"find":"{denied}","filter":{{"secret":"v"}}}}"#),
        None,
    )
    .await;
    narrow.drop().await;

    assert!(ok.is_ok(), "{ok:?}");
    let Err(ExecError::Rejected(rejection)) = refused else {
        panic!("expected a rejection, got {refused:?}");
    };
    assert_eq!(rejection.sqlstate(), "13");
    assert_eq!(rejection.to_string(), "13 not authorized");
}

/// Every connection of the pool is busy with a slow read: the next caller
/// waits outside its statement budget and gets `unavailable` after the 5 s
/// acquire wait — not a `timeout` for a command that never started.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_saturated_pool_is_unavailable_not_timeout() {
    let coll = unique_collection("mongosat");
    let docs: Vec<Document> = (0..8_000_i64).map(|i| doc! { "i": i }).collect();
    insert(&coll, docs).await;
    let sizing = PoolSizing {
        max_connections: 1,
        ..PoolSizing::default()
    };
    let a = MongoAdapter::open(
        &server("mongo-sat"),
        &database(),
        sizing,
        DetachedTasks::new(),
    )
    .await
    .expect("client builds");
    // Unindexed self-join: O(n²), and the `$match` keeps any row from
    // coming back early, so it runs until its 10 s budget stops it.
    let slow = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$lookup":{{"from":"{coll}","localField":"i","foreignField":"unmatched","as":"m"}}}},{{"$match":{{"m.0":{{"$exists":true}}}}}}],"cursor":{{"batchSize":0}}}}"#
    );
    let count = format!(r#"{{"count":"{coll}","query":{{}}}}"#);

    let slow_call = run(&a, &slow, Some(10_000));
    let waiting_call = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        (run(&a, &count, Some(1_000)).await, started.elapsed())
    };
    let (slow_result, (waited, elapsed)) = tokio::join!(slow_call, waiting_call);
    drop_collection(&side_client(), &coll).await;

    assert!(
        matches!(slow_result, Err(ExecError::Timeout)),
        "{slow_result:?}"
    );
    assert!(matches!(waited, Err(ExecError::Unavailable)), "{waited:?}");
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(8),
        "waited {elapsed:?}"
    );
}
