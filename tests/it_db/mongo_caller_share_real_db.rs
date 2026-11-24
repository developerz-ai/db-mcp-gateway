//! Mongo `describe_schema` inside a caller scope: the listing's catalog
//! commands each take the caller's pool share, so the call itself must not
//! hold one too — with a share of one it would wait on itself and fail
//! `unavailable`.
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use std::time::{Duration, Instant};

use crate::common::mongo_target::{
    database, drop_collection, server, side_client, unique_collection,
};
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::exec::adapter::{Caller, for_caller};
use db_mcp_gateway::exec::{DbAdapter, MongoAdapter, PoolSizing, SchemaQuery};
use mongodb::bson::doc;
use uuid::Uuid;

/// Well under the 5 s caller-slot wait a nested acquisition would sit out.
const PROMPT: Duration = Duration::from_secs(3);

async fn adapter(max_connections: u32) -> MongoAdapter {
    let sizing = PoolSizing {
        max_connections,
        ..PoolSizing::default()
    };
    MongoAdapter::open(
        &server("mongo-share"),
        &database(),
        sizing,
        DetachedTasks::new(),
    )
    .await
    .expect("target-mongo reachable; run `bin/dev up`")
}

async fn seeded_collection() -> String {
    let coll = unique_collection("mongoshare");
    side_client()
        .database(crate::common::mongo_target::TARGET_DB)
        .run_command(doc! { "create": coll.as_str() })
        .await
        .expect("create collection");
    coll
}

fn schema(table: &str) -> SchemaQuery<'_> {
    SchemaQuery {
        schema: None,
        table: Some(table),
        search: None,
        detail: db_mcp_gateway::exec::SchemaDetail::Columns,
        statement_timeout_ms: None,
        row_limit: 10,
        sample_limit: 0,
        request_id: Uuid::new_v4(),
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn describe_schema_with_a_share_of_one_does_not_wait_on_itself() {
    for max_connections in [1, 2] {
        let a = adapter(max_connections).await;
        let coll = seeded_collection().await;

        let started = Instant::now();
        let result = for_caller(Caller::new("solo"), a.describe_schema(schema(&coll))).await;
        let elapsed = started.elapsed();
        drop_collection(&side_client(), &coll).await;

        let result = result.unwrap_or_else(|err| {
            panic!("describe_schema failed at max_connections={max_connections}: {err:?}")
        });
        assert_eq!(result.rows.len(), 1, "{:?}", result.rows);
        assert!(
            elapsed < PROMPT,
            "describe_schema waited {elapsed:?} at max_connections={max_connections}"
        );
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn parallel_describe_schema_from_one_caller_all_succeed() {
    // Four connections: a share of three for the caller.
    let a = adapter(4).await;
    let coll = seeded_collection().await;

    let started = Instant::now();
    let results = futures::future::join_all(
        (0..3).map(|_| for_caller(Caller::new("fan-out"), a.describe_schema(schema(&coll)))),
    )
    .await;
    let elapsed = started.elapsed();
    drop_collection(&side_client(), &coll).await;

    for result in &results {
        assert!(result.is_ok(), "{result:?}");
    }
    assert!(elapsed < PROMPT, "three describes took {elapsed:?}");
}
