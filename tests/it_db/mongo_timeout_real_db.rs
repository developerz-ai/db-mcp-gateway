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

use std::sync::Arc;
use std::time::{Duration, Instant};

use mongodb::bson::{Document, doc};
use serde_json::Value;
use uuid::Uuid;

use crate::common::audit::{DispatchSinks, latest_audit};
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use crate::common::mongo_target::{
    TARGET_DB, adapter, drop_collection, server, side_client, unique_collection,
};
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{Action, ConfigFile, Constraints, Grant, Permission};
use db_mcp_gateway::exec::{
    Access, AdapterRegistry, DEFAULT_STATEMENT_TIMEOUT_MS, DbAdapter, ExecError, ExecQuery,
};
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::tools::run_query;
use db_mcp_gateway::tools::{RequestContext, ToolCtx, Upstream};

const SERVER_NAME: &str = "mongo";
const GROUP: &str = "mongo-timeout-test";

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
    let a = adapter(SERVER_NAME).await;
    let coll = unique_collection("mongotmo");
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
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await
        .expect("find runs");
        observed.push(profiled_max_time_ms(&coll).await);
    }

    set_profiling(0).await;
    drop_collection(&side_client(), &coll).await;

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
    let a = adapter(SERVER_NAME).await;
    let coll = unique_collection("mongotmo");
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
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await;
    let elapsed = started.elapsed();

    drop_collection(&side_client(), &coll).await;

    assert!(
        matches!(result, Err(ExecError::Timeout)),
        "expected ExecError::Timeout — the getMore ran past the 200ms grant, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "call took {elapsed:?} — the budget did not bound it"
    );
}

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "mongo-timeout-test@example.com".to_string(),
        groups: vec![GROUP.to_string()],
        issued_at: chrono::Utc::now(),
        kind: db_mcp_gateway::auth::IdentityKind::Sso,
    }
}

fn config_with_timeout(statement_timeout_ms: Option<u32>) -> ConfigFile {
    ConfigFile {
        gateway: Default::default(),
        servers: vec![server(SERVER_NAME)],
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
        admin: Default::default(),
        permissions_store: None,
        service_accounts: Vec::new(),
        logging: Default::default(),
    }
}

/// The tool-level error code carried inside a `tools/call` response body.
fn tool_error_code(response: &db_mcp_gateway::mcp::jsonrpc::Response) -> Option<String> {
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
    let coll = unique_collection("mongotmo");
    // Enough documents that an unindexed sort + group cannot finish inside
    // a 1ms budget.
    seed(&coll, 5_000).await;

    let user = format!("mongo-timeout-{}", Uuid::new_v4().simple());
    let identity = identity(&user);
    let config = config_with_timeout(Some(1));
    let registry = AdapterRegistry::new();
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let permissions_cache = PermissionsCache::new(repo, Duration::from_secs(30));
    let sql = format!(
        r#"{{"aggregate":"{coll}","pipeline":[{{"$sort":{{"i":-1}}}},{{"$group":{{"_id":null,"ns":{{"$push":"$i"}}}}}}],"cursor":{{}}}}"#
    );

    // Bounded retry: a very fast box can occasionally squeak a 5k-doc sort
    // past a 1ms budget. Five attempts that all beat it would mean the
    // budget is not being enforced at all, which is the regression.
    let sinks = DispatchSinks::new(&[]);
    let mut code = None;
    for _ in 0..5 {
        // A fresh gateway request id per attempt, as the transport mints one:
        // the intent row is keyed on it, so reusing one (e.g. the nil UUID
        // from `Default`) collides with an earlier attempt's row.
        let ctx = RequestContext {
            request_id: Uuid::new_v4(),
            ip: None,
            agent_client: None,
            upstream: Upstream::Absent,
        };
        let tool_ctx = ToolCtx {
            identity: &identity,
            config: &config,
            registry: &registry,
            permissions_cache: &permissions_cache,
            state_db: &pool,
            audit_sinks: &sinks.sinks,
            detached: &sinks.tasks,
            request: &ctx,
        };
        let response = run_query::run(
            tool_ctx,
            Value::from(Uuid::new_v4().to_string()),
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

    drop_collection(&side_client(), &coll).await;

    assert_eq!(
        code.as_deref(),
        Some("timeout"),
        "expected the `timeout` tool code within 5 attempts"
    );

    let row = latest_audit(&pool, &user, "run_query", "run_query dispatch").await;
    assert_eq!(row.outcome, "timeout");
    assert_eq!(row.server.as_deref(), Some(SERVER_NAME));
    assert_eq!(row.database.as_deref(), Some(TARGET_DB));
    assert_eq!(row.db_type.as_deref(), Some("mongo"));

    delete_audit_calls(&pool, &user).await;
}
