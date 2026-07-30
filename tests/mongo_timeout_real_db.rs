//! Real-mongo tests for the gateway's statement-timeout contract on the
//! mongo adapter. Targets the `target-mongo` service from
//! `docker-compose.dev.yml` (mongo:7 on localhost:27018).
//!
//! Three properties, all of which the adapter used to violate:
//!
//! 1. A grant that declines to set `statement_timeout_ms` still gets a
//!    bounded operation — `maxTimeMS` is present with the gateway ceiling.
//! 2. A grant asking for more than the ceiling is clamped down to it; a
//!    grant may only tighten (most-restrictive-wins).
//! 3. An operation that blows the budget — including one whose work all
//!    happens after the initial batch — surfaces the typed timeout error
//!    *and* lands an audit row with `outcome = "timeout"`.
//!
//! Evidence for (1) and (2) comes from mongo's own profiler
//! (`system.profile` records the command document as the server received
//! it), not from re-reading gateway state — the target DB is never mocked.

use std::time::{Duration, Instant};

use mongodb::bson::{Document, doc};
use serde_json::Value;
use uuid::Uuid;

use db_mcp_gateway::audit;
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::config::{
    Action, ConfigFile, Constraints, Database, Grant, Password, Permission, Server, ServerKind, Tls,
};
use db_mcp_gateway::exec::{
    AdapterRegistry, DEFAULT_STATEMENT_TIMEOUT_MS, DbAdapter, ExecError, ExecQuery, MongoAdapter,
};
use db_mcp_gateway::state;
use db_mcp_gateway::tools::RequestContext;
use db_mcp_gateway::tools::run_query;

const TARGET_HOST: &str = "localhost";
const TARGET_PORT: u16 = 27018;
const TARGET_USER: &str = "app";
const TARGET_PASSWORD: &str = "app-dev-only";
const TARGET_DB: &str = "app";
const SERVER_NAME: &str = "mongo";
const GROUP: &str = "mongo-timeout-test";

fn server() -> Server {
    Server {
        name: SERVER_NAME.to_string(),
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
        // docker-compose.dev.yml `target-mongo`.
        auth_database: Some("admin".to_string()),
    }
}

async fn adapter() -> MongoAdapter {
    MongoAdapter::open(&server(), &database())
        .await
        .expect("target-mongo reachable; run `bin/dev up`")
}

/// Side-channel client for setup / teardown / inspection — bypasses the
/// rejector so we can seed, drop, and read `system.profile`. NEVER a
/// production path: it has root-equivalent access.
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

fn unique_collection() -> String {
    format!("mongotmo_{}", Uuid::new_v4().simple())
}

/// Bulk-insert `count` trivial documents. Chunked because a single
/// `insert` command is capped at 100k documents (and 16MB of BSON).
async fn seed(collection: &str, count: usize) {
    const CHUNK: usize = 20_000;
    let client = side_client();
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

async fn drop_collection(collection: &str) {
    let _ = side_client()
        .database(TARGET_DB)
        .run_command(doc! { "drop": collection })
        .await;
}

/// `profile: 2` records every operation against `app` into
/// `app.system.profile`, including the command document verbatim.
async fn set_profiling(level: i32) {
    side_client()
        .database(TARGET_DB)
        .run_command(doc! { "profile": level })
        .await
        .expect("setProfilingLevel");
}

/// The `maxTimeMS` mongo actually received on the most recent profiled
/// `find` against `collection`. `None` when the profiler has no entry.
async fn profiled_max_time_ms(collection: &str) -> Option<i64> {
    use futures::StreamExt;
    let mut cursor = side_client()
        .database(TARGET_DB)
        .run_cursor_command(doc! {
            "find": "system.profile",
            "filter": { "command.find": collection },
            "sort": { "ts": -1 },
            "limit": 1,
        })
        .await
        .expect("read system.profile");
    let entry = cursor.next().await?.expect("profile entry decodes");
    let command = entry.get_document("command").ok()?;
    // The gateway writes an i64; mongo may echo it back narrowed.
    command
        .get_i64("maxTimeMS")
        .or_else(|_| command.get_i32("maxTimeMS").map(i64::from))
        .ok()
}

/// Every command carries a `maxTimeMS`, and it is always the *effective*
/// budget: the gateway ceiling when the grant is silent, the ceiling again
/// when the grant asks for more than the ceiling, and the grant's own value
/// only when that value is tighter.
///
/// Without this, a grant with no `statement_timeout_ms` produced a command
/// with no `maxTimeMS` at all (unbounded server-side operation) and a grant
/// asking for an hour was honoured verbatim — a grant loosening past the
/// gateway ceiling, which inverts most-restrictive-wins.
///
/// One test rather than three because it toggles database-wide profiling;
/// splitting it would let two tests race on that global.
#[tokio::test]
async fn command_always_carries_the_clamped_max_time_ms() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&coll, 3).await;
    set_profiling(2).await;

    let ceiling = i64::from(DEFAULT_STATEMENT_TIMEOUT_MS);
    let cases: [(Option<u32>, i64); 3] = [
        // Grant declines to cap → gateway ceiling, never absent.
        (None, ceiling),
        // Grant asks for an hour → clamped to the ceiling.
        (Some(3_600_000), ceiling),
        // Grant is tighter than the ceiling → the grant wins.
        (Some(5_000), 5_000),
    ];

    let sql = format!(r#"{{"find":"{coll}","filter":{{}}}}"#);
    let mut observed = Vec::new();
    for (grant, _) in cases {
        a.execute(ExecQuery {
            sql: &sql,
            binds: &[],
            statement_timeout_ms: grant,
            row_limit: 100,
        })
        .await
        .expect("find runs");
        observed.push(profiled_max_time_ms(&coll).await);
    }

    set_profiling(0).await;
    drop_collection(&coll).await;

    for ((grant, expected), got) in cases.into_iter().zip(observed) {
        assert_eq!(
            got,
            Some(expected),
            "grant statement_timeout_ms = {grant:?} must reach mongo as maxTimeMS = {expected}"
        );
    }
}

/// The budget covers work that happens *after* the initial batch.
/// `cursor: {batchSize: 0}` makes that split explicit — mongo hands back the
/// cursor immediately having done no work at all, then runs the entire
/// pipeline inside the first `getMore`. Run the same pipeline under a grant
/// that declines to set `statement_timeout_ms` and the pre-fix adapter had
/// nothing to stop it: no `maxTimeMS`, no deadline, an O(n²) self-join left
/// to run as long as it liked.
///
/// Which half stops it is deliberately not asserted. Mongo carries an
/// aggregation cursor's deadline into `getMore`, so in practice `maxTimeMS`
/// fires first here (~200ms) and we get the precise `MaxTimeMSExpired`
/// mapping; the Tokio guard is the backstop for the cursor kinds where the
/// server does not carry it. The contract under test is the bound itself.
#[tokio::test]
async fn expensive_cursor_read_is_bounded_by_the_budget() {
    let a = adapter().await;
    let coll = unique_collection();
    seed(&coll, 4_000).await;

    // Unindexed self-join: every input document triggers a full collection
    // scan, so the pipeline is O(n²) — far more work than the budget allows.
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$lookup":{{"from":"{coll}","localField":"i","foreignField":"unmatched","as":"m"}}}}],"cursor":{{"batchSize":0}}}}"#
    );
    let started = Instant::now();
    let result = a
        .execute(ExecQuery {
            sql: &sql,
            binds: &[],
            // 200ms grant → 700ms outer budget (200 + the adapter's slack).
            statement_timeout_ms: Some(200),
            // High enough that the row cap can't be what stops the drain.
            row_limit: 1_000_000,
        })
        .await;
    let elapsed = started.elapsed();

    drop_collection(&coll).await;

    assert!(
        matches!(result, Err(ExecError::Timeout)),
        "expected ExecError::Timeout — the getMore ran past the 200ms grant, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "call took {elapsed:?} — the budget did not bound it"
    );
}

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn state_pool() -> sqlx::PgPool {
    state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "mongo-timeout-test@example.com".to_string(),
        groups: vec![GROUP.to_string()],
        issued_at: chrono::Utc::now(),
    }
}

fn config_with_timeout(statement_timeout_ms: Option<u32>) -> ConfigFile {
    ConfigFile {
        servers: vec![server()],
        permissions: vec![Permission {
            group: GROUP.to_string(),
            grants: vec![Grant {
                server: SERVER_NAME.to_string(),
                database: TARGET_DB.to_string(),
                action: Action::QueryRead,
                constraints: Constraints {
                    require_reason: false,
                    row_limit: None,
                    statement_timeout_ms,
                },
            }],
        }],
        admin: None,
        permissions_store: None,
    }
}

/// The tool-level error code carried inside a `tools/call` response body.
fn tool_error_code(response: &db_mcp_gateway::transport::jsonrpc::Response) -> Option<String> {
    let value = serde_json::to_value(response).ok()?;
    let text = value["result"]["content"][0]["text"].as_str()?;
    let body: Value = serde_json::from_str(text).ok()?;
    body["code"].as_str().map(str::to_string)
}

/// End-to-end: an operation that exceeds its budget returns the `timeout`
/// tool code AND lands an audit row with `outcome = "timeout"`. CLAUDE.md
/// non-negotiable #4 — the audit write is synchronous and every failure
/// mode is recorded, mongo included.
#[tokio::test]
async fn slow_operation_times_out_and_writes_timeout_audit_row() {
    let pool = state_pool().await;
    let coll = unique_collection();
    // Enough documents that an unindexed sort + group cannot finish inside
    // a 1ms budget.
    seed(&coll, 5_000).await;

    let user = format!("mongo-timeout-{}", Uuid::new_v4().simple());
    let identity = identity(&user);
    let config = config_with_timeout(Some(1));
    let registry = AdapterRegistry::new();
    let ctx = RequestContext::default();
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$sort":{{"i":-1}}}},{{"$group":{{"_id":null,"ns":{{"$push":"$i"}}}}}}],"cursor":{{}}}}"#
    );

    // Bounded retry: a very fast box can occasionally squeak a 5k-doc sort
    // past a 1ms budget. Five attempts that all beat it would mean the
    // budget is not being enforced at all, which is the regression.
    let mut code = None;
    for _ in 0..5 {
        let response = run_query::run(
            Value::from(Uuid::new_v4().to_string()),
            &identity,
            &config,
            &registry,
            None,
            Some(&pool),
            &ctx,
            Some(serde_json::json!({
                "server": SERVER_NAME,
                "database": TARGET_DB,
                "sql": sql,
            })),
        )
        .await;
        code = tool_error_code(&response);
        if code.as_deref() == Some("timeout") {
            break;
        }
    }

    drop_collection(&coll).await;

    assert_eq!(
        code.as_deref(),
        Some("timeout"),
        "expected the `timeout` tool code within 5 attempts"
    );

    let row = audit::latest_for_user_tool(&pool, &user, "run_query")
        .await
        .expect("audit query runs")
        .expect("audit row was written");
    assert_eq!(row.outcome, "timeout");
    assert_eq!(row.server.as_deref(), Some(SERVER_NAME));
    assert_eq!(row.database.as_deref(), Some(TARGET_DB));
    assert_eq!(row.db_type.as_deref(), Some("mongo"));

    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&pool)
        .await
        .expect("cleanup");
}
