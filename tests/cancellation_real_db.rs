//! Integration tests for the exec-layer cancellation guarantee:
//! when the query future is dropped (agent disconnect), `CancelOnDrop` fires
//! `pg_cancel_backend` on the running Postgres backend so the query terminates
//! promptly rather than running until `statement_timeout`.
//!
//! Two properties under test:
//!
//! 1. **Backend cancelled** — after the task is aborted the backend PID is no
//!    longer in the `active` state in `pg_stat_activity`.  Without
//!    `pg_cancel_backend` the backend would remain `active` for the full 30 s
//!    `statement_timeout`; the cancel terminates it within milliseconds.
//!
//! 2. **Audit row** — a full `audit_dispatch` + real `PgAdapter::execute` path
//!    that is aborted mid-query leaves `outcome = "cancelled"` in the audit log.
//!    Both the `CancelOnDrop` (exec layer) and `CancelledAuditGuard` (dispatch
//!    layer) must fire on the same abort.
//!
//! ## pg_stat_activity query notes
//!
//! The monitoring query used to find the sleeping backend itself contains the
//! sleep SQL as a string literal, so a `LIKE` filter would match the monitor
//! connection.  We use exact equality (`query = 'SELECT pg_sleep(N)'`) together
//! with `AND pid != pg_backend_pid()` to avoid false positives.  Each test uses
//! a distinct sleep duration (31 vs 32 seconds) so concurrent test runs cannot
//! capture each other's backends.
//!
//! After `pg_cancel_backend` the backend transitions from `active` →
//! `idle in transaction (aborted)`.  We check `state = 'active'` (NOT
//! `state != 'idle'`) so the assertion passes as soon as the cancel is
//! delivered — the subsequent ROLLBACK is not required for the test.

use std::sync::Arc;
use std::time::Duration;

use db_mcp_gateway::audit;
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{DbAdapter, ExecQuery, PgAdapter};
use db_mcp_gateway::state;
use db_mcp_gateway::tools::audit_dispatch::{AuditHeader, Outcome, RequestContext, audit_dispatch};
use db_mcp_gateway::transport::jsonrpc::Response;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL")
        .unwrap_or_else(|_| "postgres://gateway:gateway-dev-only@localhost:5433/gateway".into())
}

fn target_db_url() -> String {
    std::env::var("TARGET_DB_URL")
        .unwrap_or_else(|_| "postgres://app:app-dev-only@localhost:5434/app".into())
}

fn test_server() -> Server {
    Server {
        name: "target".into(),
        kind: ServerKind::Postgres,
        description: String::new(),
        host: "localhost".into(),
        port: 5434,
        tls: Tls::Insecure,
        databases: vec![],
    }
}

fn test_database() -> Database {
    Database {
        name: "app".into(),
        role: "app".into(),
        password: Password::Literal("app-dev-only".into()),
        description: String::new(),
        auth_database: None,
    }
}

fn test_identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "cancel-real-db@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
    }
}

/// Verify that dropping a `PgAdapter::execute` future mid-query fires
/// `pg_cancel_backend` and the backend stops actively executing.
///
/// Uses `pg_sleep(31)` (distinct from the companion test's `pg_sleep(32)`)
/// so the exact-match pg_stat_activity filter doesn't cross-contaminate when
/// both tests run in parallel.
#[tokio::test]
async fn pg_cancel_backend_fires_when_execute_future_dropped() {
    let monitor = PgPoolOptions::new()
        .max_connections(2)
        .connect(&target_db_url())
        .await
        .expect("monitor connection to target DB (run `bin/dev up`)");

    let adapter = Arc::new(
        PgAdapter::open(&test_server(), &test_database())
            .await
            .expect("PgAdapter open"),
    );

    // Spawn a long-running query with a 30 s timeout so it outlives any
    // reasonable test run without the cancel.  CancelOnDrop (inside
    // `run_query_inner`) fires `pg_cancel_backend` when this task is aborted.
    let adapter_task = adapter.clone();
    let task = tokio::spawn(async move {
        adapter_task
            .execute(ExecQuery {
                sql: "SELECT pg_sleep(31)",
                binds: &[],
                statement_timeout_ms: Some(30_000),
                row_limit: 1,
            })
            .await
    });

    // Give the query time to reach the Postgres backend.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Exact-match filter: avoids matching the monitoring query itself (which
    // contains the string 'pg_sleep(31)' as a literal substring) and avoids
    // cross-contamination with the companion test (which uses 'pg_sleep(32)').
    // `pid != pg_backend_pid()` is belt-and-suspenders.
    let pid: Option<i32> = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE query = 'SELECT pg_sleep(31)' \
         AND state = 'active' \
         AND pid != pg_backend_pid() \
         LIMIT 1",
    )
    .fetch_optional(&monitor)
    .await
    .expect("pg_stat_activity lookup");

    let pid = pid.expect(
        "pg_sleep(31) backend should be visible in pg_stat_activity — \
         is the target DB up? (run `bin/dev up`)",
    );

    // Abort the task.  This drops the `PgAdapter::execute` future chain:
    //   tokio::time::timeout → run_query_inner → CancelOnDrop::drop fires
    //   → tokio::spawn(pg_cancel_backend(pid))
    task.abort();

    // Wait for the detached pg_cancel_backend spawn to execute.  600ms is
    // generous: the cancel is a simple protocol message; the backend typically
    // stops within a single scheduling tick.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // After the cancel the backend transitions active → idle-in-tx-aborted.
    // Check that it is no longer in the 'active' state.
    let still_active: Option<i32> = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE pid = $1 AND state = 'active'",
    )
    .bind(pid)
    .fetch_optional(&monitor)
    .await
    .expect("pg_stat_activity follow-up");

    assert!(
        still_active.is_none(),
        "backend pid={pid} should no longer be 'active' after task abort — \
         pg_cancel_backend may not have fired (CancelOnDrop wiring broken)"
    );
}

/// Full-stack cancellation: `audit_dispatch` + real `PgAdapter::execute`
/// aborted mid-query leaves BOTH the DB backend cancelled AND an
/// `outcome = "cancelled"` audit row.
///
/// Uses `pg_sleep(32)` (distinct from `pg_cancel_backend_fires…` which uses
/// `pg_sleep(31)`) to avoid concurrent-test cross-contamination.
#[tokio::test]
async fn cancelled_dispatch_cancels_pg_backend_and_writes_audit_row() {
    let state_pool = state::connect(&state_db_url(), 5)
        .await
        .expect("state DB (run `bin/dev up`)");

    let monitor = PgPoolOptions::new()
        .max_connections(2)
        .connect(&target_db_url())
        .await
        .expect("monitor connection to target DB");

    let adapter = Arc::new(
        PgAdapter::open(&test_server(), &test_database())
            .await
            .expect("PgAdapter open"),
    );

    let user = format!("cancel-rdb-{}", Uuid::new_v4().simple());
    let request_id = Value::from(Uuid::new_v4().to_string());
    let ctx = RequestContext::default();

    let adapter_task = adapter.clone();
    let state_pool_task = state_pool.clone();
    let user_task = user.clone();
    let id_task = request_id.clone();

    // Spawn a task running a real pg_sleep(32) through the full
    // audit_dispatch → PgAdapter::execute stack.  When the task is aborted:
    //   - CancelledAuditGuard fires → writes outcome="cancelled" to state DB
    //   - CancelOnDrop fires        → pg_cancel_backend stops the backend
    let task = tokio::spawn(async move {
        let id = id_task.clone();
        let identity = test_identity(&user_task);
        let header = AuditHeader {
            tool: "run_query",
            server: Some("target"),
            database: Some("app"),
            sql: Some("SELECT pg_sleep(32)"),
            reason: None,
            db_type: Some("postgres"),
        };
        // The work future runs a real DB query; the task will be aborted
        // before it completes.  The Outcome arms are unreachable in normal
        // test execution but must compile for the type to resolve.
        let work = {
            let id_out = id.clone();
            async move {
                let result = adapter_task
                    .execute(ExecQuery {
                        sql: "SELECT pg_sleep(32)",
                        binds: &[],
                        statement_timeout_ms: Some(30_000),
                        row_limit: 1,
                    })
                    .await;
                match result {
                    Ok(_) => Outcome {
                        response: Response::result(id_out, &serde_json::json!({"ok": true})),
                        code: "success",
                        elapsed_ms: Some(0),
                        row_count: Some(0),
                        truncated: Some(false),
                        error_message: None,
                    },
                    Err(_) => Outcome {
                        response: Response::result(id_out, &serde_json::json!({"ok": false})),
                        code: "internal",
                        elapsed_ms: None,
                        row_count: None,
                        truncated: None,
                        error_message: Some("internal error".into()),
                    },
                }
            }
        };
        audit_dispatch(
            id_task,
            &identity,
            Some(&state_pool_task),
            &ctx,
            header,
            work,
        )
        .await
    });

    // Give the query time to reach the Postgres backend.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Find the pg_sleep(32) backend using exact-match to avoid matching the
    // monitoring query itself (see module-level notes).
    let pid: Option<i32> = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE query = 'SELECT pg_sleep(32)' \
         AND state = 'active' \
         AND pid != pg_backend_pid() \
         LIMIT 1",
    )
    .fetch_optional(&monitor)
    .await
    .expect("pg_stat_activity before abort");

    let pid = pid.expect("pg_sleep(32) backend should be visible in pg_stat_activity before abort");

    // Abort → both CancelOnDrop and CancelledAuditGuard fire on the same drop.
    task.abort();

    // Wait for both detached spawns (pg_cancel_backend + audit INSERT).
    // 800ms is generous; both are small network round-trips to localhost.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // 1. DB backend must no longer be actively running the query.
    let still_active: Option<i32> =
        sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE pid = $1 AND state = 'active'")
            .bind(pid)
            .fetch_optional(&monitor)
            .await
            .expect("pg_stat_activity follow-up");

    assert!(
        still_active.is_none(),
        "backend pid={pid} should no longer be 'active' after task abort — \
         CancelOnDrop / pg_cancel_backend may not have fired"
    );

    // 2. Audit row must be present with outcome = "cancelled".
    let row = audit::latest_for_user_tool(&state_pool, &user, "run_query")
        .await
        .expect("audit query runs")
        .unwrap_or_else(|| {
            panic!("no audit row for user={user} — CancelledAuditGuard did not fire")
        });

    assert_eq!(row.outcome, "cancelled", "audit outcome mismatch");
    assert_eq!(row.server.as_deref(), Some("target"));
    assert_eq!(row.database.as_deref(), Some("app"));
    assert_eq!(row.db_type.as_deref(), Some("postgres"));
    assert_eq!(
        row.error_message.as_deref(),
        Some("client disconnected before completion"),
    );

    // Cleanup so reruns don't accumulate rows for this user.
    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&state_pool)
        .await
        .expect("cleanup");
}

/// Regression for the "cancel through the pool the stuck queries are pinning"
/// bug (#136). With the fix, `CancelOnDrop` fires on a dedicated cancel pool,
/// so a fully-pinned query pool does NOT block the cancels. This test spawns
/// enough hung queries to saturate the query pool, aborts them all at once,
/// and asserts every backend transitions out of `active` well before
/// `statement_timeout` could plausibly end them.
///
/// Under the pre-fix code, all N cancel spawns would `pool.acquire()` on the
/// query pool — the exact pool whose N slots are held by the N stuck
/// backends the cancels are trying to free. Each `acquire()` would wait for
/// a slot that only opens when its own target's `statement_timeout` fires.
///
/// Uses `pg_sleep(33)` — distinct from 31/32 above — to avoid cross-test
/// pg_stat_activity contamination when the file's tests run in parallel.
#[tokio::test]
async fn concurrent_aborts_do_not_queue_on_query_pool() {
    let monitor = PgPoolOptions::new()
        .max_connections(2)
        .connect(&target_db_url())
        .await
        .expect("monitor connection to target DB (run `bin/dev up`)");

    let adapter = Arc::new(
        PgAdapter::open(&test_server(), &test_database())
            .await
            .expect("PgAdapter open"),
    );

    // Match `DEFAULT_POOL_MAX_CONNECTIONS` — saturate the query pool so every
    // slot is held by a pg_sleep. If cancels queued on this pool (the bug),
    // none would run until statement_timeout expired.
    const HUNG_QUERIES: usize = 5;
    let mut tasks = Vec::with_capacity(HUNG_QUERIES);
    for _ in 0..HUNG_QUERIES {
        let adapter_task = adapter.clone();
        tasks.push(tokio::spawn(async move {
            adapter_task
                .execute(ExecQuery {
                    sql: "SELECT pg_sleep(33)",
                    binds: &[],
                    statement_timeout_ms: Some(30_000),
                    row_limit: 1,
                })
                .await
        }));
    }

    // Wait until all N backends are visible as `active` — the test premise
    // is that the pool is FULLY pinned before we drop.
    let mut pids: Vec<i32> = Vec::new();
    for _ in 0..40 {
        pids = sqlx::query_scalar(
            "SELECT pid FROM pg_stat_activity \
             WHERE query = 'SELECT pg_sleep(33)' \
             AND state = 'active' \
             AND pid != pg_backend_pid()",
        )
        .fetch_all(&monitor)
        .await
        .expect("pg_stat_activity lookup");
        if pids.len() >= HUNG_QUERIES {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        pids.len(),
        HUNG_QUERIES,
        "expected {HUNG_QUERIES} pg_sleep(33) backends visible, saw {}: \
         did the query pool saturate? (run `bin/dev up`)",
        pids.len(),
    );

    // Abort every task simultaneously. Under the fix, each `CancelOnDrop` spawns
    // a cancel on the *cancel* pool; under the bug, each would queue on the
    // saturated query pool.
    for t in &tasks {
        t.abort();
    }

    // With the fix, cancels run within a couple of tokio ticks. 1500ms is
    // generous for five parallel cancels over a size-2 cancel pool (two
    // concurrent + serialised remainder — still well below statement_timeout).
    // Under the bug, this budget expires long before any cancel lands and
    // every pid is still `active`.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let still_active: Vec<i32> = sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE pid = ANY($1) AND state = 'active'",
    )
    .bind(&pids)
    .fetch_all(&monitor)
    .await
    .expect("pg_stat_activity follow-up");

    assert!(
        still_active.is_empty(),
        "{}/{} backends still active {}ms after abort — cancels are queueing \
         on the query pool (bug), or the cancel pool is undersized. \
         active pids: {:?}",
        still_active.len(),
        HUNG_QUERIES,
        1500,
        still_active,
    );
}
