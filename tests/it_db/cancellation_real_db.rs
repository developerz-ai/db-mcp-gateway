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
//! Each test tags its SQL with a unique `/* marker */` comment and finds its
//! backends by that marker, so concurrent tests (and reruns) never capture
//! each other's backends; `pid != pg_backend_pid()` keeps the monitor query,
//! which contains the marker too, out of the match. Every wait polls
//! `pg_stat_activity` until a deadline — no fixed sleeps.
//!
//! After `pg_cancel_backend` the backend transitions from `active` →
//! `idle in transaction (aborted)`.  We check `state = 'active'` (NOT
//! `state != 'idle'`) so the assertion passes as soon as the cancel is
//! delivered — the subsequent ROLLBACK is not required for the test.

use crate::common;
use std::sync::Arc;
use std::time::Duration;

use crate::common::audit::{DispatchSinks, latest_audit};
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::{state_pool, target_db_url};
use crate::common::pg_target;
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::exec::{
    Access, DEFAULT_POOL_MAX_CONNECTIONS, DbAdapter, ExecQuery, PgAdapter, PoolSizing,
};
use db_mcp_gateway::mcp::jsonrpc::Response;
use db_mcp_gateway::tools::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, Reply, RequestContext, Upstream, audit_dispatch,
};
use serde_json::Value;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

/// Bound on every wait: far below the 30 s `statement_timeout`, so only a
/// fired cancel (not the timeout) can clear a backend in time.
const WAIT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// `SELECT pg_sleep(30)` tagged with a fresh marker; returns `(marker, sql)`.
fn tagged_sleep(test: &str) -> (String, String) {
    let marker = format!("{test}-{}", Uuid::new_v4().simple());
    let sql = format!("SELECT pg_sleep(30) /* {marker} */");
    (marker, sql)
}

/// PIDs of `active` backends whose query carries `marker`.
async fn active_pids(monitor: &PgPool, marker: &str) -> Vec<i32> {
    sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity \
         WHERE state = 'active' AND pid != pg_backend_pid() \
         AND position($1 in query) > 0",
    )
    .bind(marker)
    .fetch_all(monitor)
    .await
    .expect("pg_stat_activity lookup")
}

/// Poll until exactly `count` marked backends are active; returns the last
/// observed PIDs, whatever their number, once the deadline passes.
async fn wait_for_active(monitor: &PgPool, marker: &str, count: usize) -> Vec<i32> {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let pids = active_pids(monitor, marker).await;
        if pids.len() == count || tokio::time::Instant::now() >= deadline {
            return pids;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll until the detached `cancelled` audit write lands (or the deadline).
async fn wait_for_audit_row(pool: &PgPool, user_sub: &str) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while common::audit::find_audit(pool, user_sub, "run_query")
        .await
        .is_none()
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn test_identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "cancel-real-db@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
        kind: db_mcp_gateway::auth::IdentityKind::Sso,
    }
}

/// Verify that dropping a `PgAdapter::execute` future mid-query fires
/// `pg_cancel_backend` and the backend stops actively executing.
///
#[tokio::test]
async fn pg_cancel_backend_fires_when_execute_future_dropped() {
    let monitor = PgPoolOptions::new()
        .max_connections(2)
        .connect(&target_db_url())
        .await
        .expect("monitor connection to target DB (run `bin/dev up`)");

    let adapter = Arc::new(
        PgAdapter::open(
            &pg_target::server(),
            &pg_target::database(),
            PoolSizing::default(),
            DetachedTasks::new(),
        )
        .await
        .expect("PgAdapter open"),
    );

    // Spawn a long-running query with a 30 s timeout so it outlives any
    // reasonable test run without the cancel.  CancelOnDrop (inside
    // `run_query_inner`) fires `pg_cancel_backend` when this task is aborted.
    let (marker, sql) = tagged_sleep("drop-cancel");
    let adapter_task = adapter.clone();
    let task = tokio::spawn(async move {
        adapter_task
            .execute(ExecQuery {
                sql: &sql,
                binds: &[],
                statement_timeout_ms: Some(30_000),
                row_limit: 1,
                access: Access::ReadOnly,
                dry_run: false,
                request_id: Uuid::new_v4(),
            })
            .await
    });

    assert_eq!(
        wait_for_active(&monitor, &marker, 1).await.len(),
        1,
        "marked backend never became active — is the target DB up? (run `bin/dev up`)"
    );

    // Abort the task.  This drops the `PgAdapter::execute` future chain:
    //   tokio::time::timeout → run_query_inner → CancelOnDrop::drop fires
    //   → tokio::spawn(pg_cancel_backend(pid))
    task.abort();

    let still_active = wait_for_active(&monitor, &marker, 0).await;
    assert!(
        still_active.is_empty(),
        "backends {still_active:?} still 'active' {WAIT:?} after task abort — \
         pg_cancel_backend may not have fired (CancelOnDrop wiring broken)"
    );
}

/// Full-stack cancellation: `audit_dispatch` + real `PgAdapter::execute`
/// aborted mid-query leaves BOTH the DB backend cancelled AND an
/// `outcome = "cancelled"` audit row.
#[tokio::test]
async fn cancelled_dispatch_cancels_pg_backend_and_writes_audit_row() {
    let state_pool = state_pool().await;

    let monitor = PgPoolOptions::new()
        .max_connections(2)
        .connect(&target_db_url())
        .await
        .expect("monitor connection to target DB");

    let adapter = Arc::new(
        PgAdapter::open(
            &pg_target::server(),
            &pg_target::database(),
            PoolSizing::default(),
            DetachedTasks::new(),
        )
        .await
        .expect("PgAdapter open"),
    );

    let user = format!("cancel-rdb-{}", Uuid::new_v4().simple());
    let request_id = Value::from(Uuid::new_v4().to_string());
    // Unique per test: the intent row is keyed on the gateway request id.
    let ctx = RequestContext {
        request_id: Uuid::new_v4(),
        ip: None,
        agent_client: None,
        upstream: Upstream::default(),
    };

    let (marker, sql) = tagged_sleep("dispatch-cancel");
    let adapter_task = adapter.clone();
    let state_pool_task = state_pool.clone();
    let user_task = user.clone();
    let id_task = request_id.clone();

    // Spawn a task running a real pg_sleep through the full
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
            sql: Some(&sql),
            reason: None,
            db_type: Some("postgres"),
        };
        // The work future runs a real DB query; the task will be aborted
        // before it completes.  The Outcome arms are unreachable in normal
        // test execution but must compile for the type to resolve.
        let work = {
            let id_out = id.clone();
            let sql = sql.clone();
            async move {
                let result = adapter_task
                    .execute(ExecQuery {
                        sql: &sql,
                        binds: &[],
                        statement_timeout_ms: Some(30_000),
                        row_limit: 1,
                        access: Access::ReadOnly,
                        dry_run: false,
                        request_id: Uuid::new_v4(),
                    })
                    .await;
                match result {
                    Ok(_) => Outcome {
                        reply: Reply::Response(Box::new(Response::result(
                            id_out,
                            &serde_json::json!({"ok": true}),
                        ))),
                        code: OutcomeCode::Success,
                        elapsed_ms: Some(0),
                        row_count: Some(0),
                        truncated: Some(false),
                        error_message: None,
                        write: None,
                    },
                    Err(_) => Outcome {
                        reply: Reply::ToolError,
                        code: OutcomeCode::Internal,
                        elapsed_ms: None,
                        row_count: None,
                        truncated: None,
                        error_message: Some("internal error".into()),
                        write: None,
                    },
                }
            }
        };
        let sinks = DispatchSinks::new(&[]);
        audit_dispatch(
            id_task,
            &identity,
            &ctx,
            header,
            sinks.store(&state_pool_task),
            work,
        )
        .await
    });

    assert_eq!(
        wait_for_active(&monitor, &marker, 1).await.len(),
        1,
        "marked backend should be visible in pg_stat_activity before abort"
    );

    // Abort → both CancelOnDrop and CancelledAuditGuard fire on the same drop.
    task.abort();

    // 1. DB backend must no longer be actively running the query.
    let still_active = wait_for_active(&monitor, &marker, 0).await;
    assert!(
        still_active.is_empty(),
        "backends {still_active:?} still 'active' after task abort — \
         CancelOnDrop / pg_cancel_backend may not have fired"
    );

    // 2. Audit row must be present with outcome = "cancelled".
    wait_for_audit_row(&state_pool, &user).await;
    let row = latest_audit(
        &state_pool,
        &user,
        "run_query",
        &format!("user={user} — CancelledAuditGuard did not fire"),
    )
    .await;

    assert_eq!(row.outcome, "cancelled", "audit outcome mismatch");
    assert_eq!(row.server.as_deref(), Some("target"));
    assert_eq!(row.database.as_deref(), Some("app"));
    assert_eq!(row.db_type.as_deref(), Some("postgres"));
    assert_eq!(
        row.error_message.as_deref(),
        Some("client disconnected before completion"),
    );

    // Cleanup so reruns don't accumulate rows for this user.
    delete_audit_calls(&state_pool, &user).await;
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
#[tokio::test]
async fn concurrent_aborts_do_not_queue_on_query_pool() {
    let monitor = PgPoolOptions::new()
        .max_connections(2)
        .connect(&target_db_url())
        .await
        .expect("monitor connection to target DB (run `bin/dev up`)");

    let adapter = Arc::new(
        PgAdapter::open(
            &pg_target::server(),
            &pg_target::database(),
            PoolSizing::default(),
            DetachedTasks::new(),
        )
        .await
        .expect("PgAdapter open"),
    );

    // Saturate the query pool so every slot is held by a pg_sleep. If cancels
    // queued on this pool (the bug), none would run until statement_timeout
    // expired. Tied to `DEFAULT_POOL_MAX_CONNECTIONS` so resizing the pool
    // can't silently leave this test under-saturated.
    const HUNG_QUERIES: usize = DEFAULT_POOL_MAX_CONNECTIONS as usize;
    let (marker, sql) = tagged_sleep("pool-saturation");
    let mut tasks = Vec::with_capacity(HUNG_QUERIES);
    for _ in 0..HUNG_QUERIES {
        let adapter_task = adapter.clone();
        let sql = sql.clone();
        tasks.push(tokio::spawn(async move {
            adapter_task
                .execute(ExecQuery {
                    sql: &sql,
                    binds: &[],
                    statement_timeout_ms: Some(30_000),
                    row_limit: 1,
                    access: Access::ReadOnly,
                    dry_run: false,
                    request_id: Uuid::new_v4(),
                })
                .await
        }));
    }

    // Wait until all N backends are visible as `active` — the test premise
    // is that the pool is FULLY pinned before we drop.
    let pids = wait_for_active(&monitor, &marker, HUNG_QUERIES).await;
    assert_eq!(
        pids.len(),
        HUNG_QUERIES,
        "expected {HUNG_QUERIES} marked backends visible, saw {}: \
         did the query pool saturate? (run `bin/dev up`)",
        pids.len(),
    );

    // Abort every task simultaneously. Under the fix, each `CancelOnDrop` spawns
    // a cancel on the *cancel* pool; under the bug, each would queue on the
    // saturated query pool.
    for t in &tasks {
        t.abort();
    }

    // With the fix, cancels land within a few ticks even over a size-2
    // cancel pool. Under the bug, none lands before statement_timeout (30 s),
    // far past the poll deadline.
    let still_active = wait_for_active(&monitor, &marker, 0).await;
    assert!(
        still_active.is_empty(),
        "{}/{HUNG_QUERIES} backends still active {WAIT:?} after abort — cancels \
         are queueing on the query pool (bug), or the cancel pool is undersized. \
         active pids: {still_active:?}",
        still_active.len(),
    );

    // Every slot was released mid-query and went back through the reset
    // hook; the pool must still serve the next caller on a clean connection.
    let next = adapter
        .execute(ExecQuery {
            sql: "SELECT current_setting('application_name') AS app",
            binds: &[],
            statement_timeout_ms: Some(5_000),
            row_limit: 1,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: Uuid::new_v4(),
        })
        .await
        .expect("query pool serves the next caller after N aborted queries");
    assert_eq!(next.rows.len(), 1);
}
