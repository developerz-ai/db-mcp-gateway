//! Real-mongo test for the cancel-on-drop guard (#141).
//!
//! Targets the `target-mongo` service from `docker-compose.dev.yml` (mongo:7
//! on localhost:27018). The dev container's `app` user is the Mongo root
//! user (`MONGO_INITDB_ROOT_USERNAME`), so it already holds the `killOp`
//! privilege — this test exercises the full kill path exactly as an
//! operator who has opted into the privilege documented in
//! `config-reference.md` §Mongo would see it, not just the best-effort
//! fallback.
//!
//! Property under test: dropping a `MongoAdapter::execute` future mid-query
//! (agent disconnect) causes `cancel::KillOpOnDrop` to fire `currentOp` +
//! `killOp`, and the operation actually stops running server-side — not just
//! "the client gave up on it".
//!
//! Audit assertion intentionally skipped in both tests: they exercise the
//! exec layer (`MongoAdapter::execute`) in isolation. The `outcome: cancelled`
//! audit row is written by the backend-agnostic drop guard in
//! `tools::audit_dispatch`, which this file never enters. Audit coverage for
//! cancellation lives in the tool-dispatch integration tests
//! (see `tests/cancellation_real_db.rs`).

use std::sync::Arc;
use std::time::Duration;

use mongodb::Client;
use mongodb::bson::{Document, doc};
use mongodb::options::{ClientOptions, Credential, ServerAddress};
use uuid::Uuid;

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{DbAdapter, ExecQuery, MongoAdapter};

const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 27018;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";
const SERVER_NAME: &str = "mongo-cancel-test";

fn server() -> Server {
    Server {
        name: SERVER_NAME.to_string(),
        kind: ServerKind::Mongo,
        description: String::new(),
        host: TARGET_HOST.to_string(),
        port: TARGET_PORT,
        tls: Tls::Insecure,
        databases: vec![],
    }
}

fn database() -> Database {
    Database {
        name: TARGET_DB.to_string(),
        role: TARGET_USER.to_string(),
        password: Password::Literal(TARGET_PASSWORD.into()),
        description: String::new(),
        auth_database: Some("admin".to_string()),
    }
}

async fn adapter() -> MongoAdapter {
    MongoAdapter::open(&server(), &database())
        .await
        .expect("target-mongo reachable; run `bin/dev up`")
}

/// Side-channel client for setup/teardown/monitoring — bypasses the
/// rejector and the gateway's marker convention entirely. NEVER a
/// production path: root-equivalent access, used only to observe
/// `currentOp` and seed data.
fn side_client() -> Client {
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

fn unique_collection() -> String {
    format!("mongocancel_{}", Uuid::new_v4().simple())
}

/// Bulk-insert `count` trivial documents, chunked under the 100k/16MB
/// per-command cap.
async fn seed(client: &Client, collection: &str, count: usize) {
    const CHUNK: usize = 20_000;
    for start in (1..=count).step_by(CHUNK) {
        let end = (start + CHUNK - 1).min(count);
        let docs: Vec<Document> = (start..=end).map(|i| doc! { "i": i as i64 }).collect();
        client
            .database(TARGET_DB)
            .run_command(doc! { "insert": collection, "documents": docs })
            .await
            .expect("seed insert");
    }
}

async fn drop_collection(client: &Client, collection: &str) {
    let _ = client
        .database(TARGET_DB)
        .run_command(doc! { "drop": collection })
        .await;
}

/// Whether `currentOp` on the admin side-channel shows an in-progress
/// operation against `collection`. Filters on `ns` (the fully-qualified
/// `db.collection` mongo stamps on every op) rather than the gateway's
/// internal `comment` marker — the test has no way to know that marker
/// ahead of time, and `ns` is a clean, collision-free proxy since each test
/// run uses a fresh UUID'd collection name.
///
/// Takes a borrowed `&Client` so the caller can reuse one connection pool
/// across the whole test — `poll_until` calls this every 50 ms, and
/// constructing a fresh `Client` per iteration would open (and never close)
/// dozens of pools per run, exhausting a constrained CI mongo container's
/// connection limit.
async fn op_running_against(client: &Client, collection: &str) -> bool {
    let ns = format!("{TARGET_DB}.{collection}");
    let admin = client.database("admin");
    let response = admin
        .run_command(doc! {
            "currentOp": 1,
            "$ownOps": false,
            "ns": &ns,
        })
        .await
        .expect("currentOp lookup");
    response
        .get_array("inprog")
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

/// Poll `op_running_against` until it returns `want` or the deadline passes.
/// Returns the last observed value. Reuses the caller's `Client` — see
/// `op_running_against` for why.
///
/// 20 ms cadence — a currentOp round-trip on localhost is a couple of ms, and
/// the "did the op appear" check needs to sample fast enough that a sub-100ms
/// aggregate on a fast CI runner still gets caught in-flight. 50 ms turned out
/// to be too coarse in practice.
async fn poll_until(client: &Client, collection: &str, want: bool, deadline: Duration) -> bool {
    let start = std::time::Instant::now();
    loop {
        let seen = op_running_against(client, collection).await;
        if seen == want || start.elapsed() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Dropping a `MongoAdapter::execute` future mid-aggregation fires
/// `cancel::KillOpOnDrop`, and the operation actually stops running on the
/// mongo server — not just "the driver-side future was abandoned".
///
/// An unindexed sort over enough documents runs long enough to observe it
/// in `currentOp` before the test aborts the task. `statement_timeout_ms`
/// is generous (30s) so `maxTimeMS` cannot be what stops it — only the
/// cancel guard's `killOp` can.
#[tokio::test]
async fn dropped_execute_future_kills_the_mongo_op() {
    let monitor = side_client();
    let coll = unique_collection();
    // Enough documents that an unindexed sort on a per-doc computed field
    // takes a comfortable few hundred ms to a couple of seconds — long enough
    // to observe in currentOp before the test aborts, short enough not to
    // make CI slow. On a fast CI runner a trivial sort of a few hundred k
    // trivial docs finishes inside a single poll interval, so the pipeline
    // adds `$addFields` + `$reduce` per doc to guarantee CPU-bound work
    // regardless of runner speed.
    seed(&monitor, &coll, 200_000).await;

    let adapter = Arc::new(adapter().await);
    // `$reduce` walks a 500-element `$range` per doc → ~100M cheap ops for
    // 200k docs, dominating the pipeline cost. Sort on the computed field
    // `h` prevents any index shortcut. Kept inline as a JSON string so the
    // full pipeline is legible next to the intent above.
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$addFields":{{"h":{{"$reduce":{{"input":{{"$range":[0,500]}},"initialValue":0,"in":{{"$add":["$$value","$$this"]}}}}}}}}}},{{"$sort":{{"h":-1,"i":-1}}}}],"cursor":{{}}}}"#
    );

    let adapter_task = adapter.clone();
    let sql_task = sql.clone();
    let task = tokio::spawn(async move {
        adapter_task
            .execute(ExecQuery {
                sql: &sql_task,
                binds: &[],
                statement_timeout_ms: Some(30_000),
                row_limit: 1,
            })
            .await
    });

    // Wait until the aggregation is actually visible as running server-side
    // before we abort — otherwise the abort could race the op even starting.
    let started = poll_until(&monitor, &coll, true, Duration::from_secs(5)).await;

    // Drop the future — same mechanism as an agent disconnecting mid-query.
    // `MongoAdapter::execute`'s `tokio::time::timeout` wraps `dispatch`,
    // which owns `kill_guard`; aborting the task drops both. Safe to run
    // even if `started == false` — abort of a task that never reached the
    // DB is a no-op.
    task.abort();

    // Poll for the op to disappear from currentOp. `killOp` is two
    // round-trips (currentOp lookup + killOp itself) on a detached spawn,
    // so give it more headroom than the pg cancellation test's single
    // `pg_cancel_backend` call.
    let still_running = poll_until(&monitor, &coll, false, Duration::from_secs(5)).await;

    // Drop the 200k-doc collection BEFORE asserting: an early panic here
    // would otherwise leave it behind on the shared dev mongo, and reruns
    // would accumulate.
    drop_collection(&monitor, &coll).await;

    assert!(
        started,
        "aggregate against {coll} never appeared in currentOp — \
         is target-mongo up? (run `bin/dev up`) or did 200k docs sort too fast?"
    );
    assert!(
        !still_running,
        "aggregate against {coll} still running in currentOp after abort — \
         KillOpOnDrop did not fire, or killOp lacks privilege (dev's `app` \
         user is mongo root and should have it — see side_client())"
    );
}

/// A command that finishes normally must NOT trigger a kill attempt — the
/// guard disarms on the normal return path in `dispatch`. Indirect check:
/// run a fast command to completion, then immediately look for any
/// in-progress op against the collection; there should be none because
/// nothing was left running AND nothing was killed (there was nothing to
/// kill — this just confirms disarm doesn't false-trigger on the DB side).
#[tokio::test]
async fn completed_command_leaves_nothing_in_current_op() {
    let monitor = side_client();
    let coll = unique_collection();
    seed(&monitor, &coll, 10).await;

    let adapter = adapter().await;
    let sql = format!(r#"{{"find":"{coll}","filter":{{}}}}"#);

    let result = adapter
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: Some(5_000),
            row_limit: 10,
        })
        .await;

    // No polling needed — the command already completed synchronously by
    // the time `execute` returned, so any in-progress state is stale noise,
    // not a race. A single check confirms nothing lingers.
    let lingering = op_running_against(&monitor, &coll).await;

    // Cleanup first, then assert — same rationale as the sister test.
    drop_collection(&monitor, &coll).await;

    assert!(result.is_ok(), "expected the find to succeed: {result:?}");
    assert!(!lingering, "a completed command left an entry in currentOp");
}
