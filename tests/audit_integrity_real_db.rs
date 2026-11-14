//! Real-DB coverage for the audit-integrity sweep (#314 slice D): the
//! retention pruner's single cutoff, the reaper's resumable cursor, and the
//! `cancelled` row of a write dropped mid-work.
//!
//! Every test scopes its rows by a fresh `user_sub` and backdates them far
//! enough that rows of concurrently running tests are never in play.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::audit::{DispatchSinks, calls_for_request, find_audit};
use common::cleanup::delete_audit_calls;
use common::env::state_pool;
use db_mcp_gateway::audit::intent::WRITE_MAY_HAVE_COMMITTED;
use db_mcp_gateway::audit::reaper::{self, ReapCursor};
use db_mcp_gateway::audit::{self, CallIntent, pruner};
use db_mcp_gateway::auth::{Identity, IdentityKind, SessionId};
use db_mcp_gateway::exec::Access;
use db_mcp_gateway::tools::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, Upstream, audit_dispatch,
};
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::Notify;
use uuid::Uuid;

/// `audit::reaper`'s advisory-lock key; held here to simulate a peer replica.
const REAPER_LOCK_KEY: i64 = 0x6462_6d63_7072_6170;

/// Reaper sweeps are global: one test's fresh-cursor sweep would settle
/// another test's intents mid-assertion. Tests that sweep hold this.
static SWEEPS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Insert an intent `age_secs` old, plus its completion `completion_lag_secs`
/// later when given. Returns the `request_id`.
async fn backdated_call(
    pool: &PgPool,
    user: &str,
    age_secs: f64,
    completion_lag_secs: Option<f64>,
) -> String {
    let request_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_call_intents \
         (request_id, occurred_at, user_sub, user_email, tool, server_name, database_name, access) \
         VALUES ($1, now() - make_interval(secs => $2), $3, 'i@example.com', 'run_query', \
                 'prod', 'app', 'read')",
    )
    .bind(&request_id)
    .bind(age_secs)
    .bind(user)
    .execute(pool)
    .await
    .expect("insert intent");
    if let Some(lag) = completion_lag_secs {
        sqlx::query(
            "INSERT INTO audit_calls \
             (id, request_id, user_sub, user_email, tool, outcome, occurred_at) \
             VALUES (gen_random_uuid(), $1, $2, 'i@example.com', 'run_query', 'success', \
                     now() - make_interval(secs => $3))",
        )
        .bind(&request_id)
        .bind(user)
        .bind(age_secs - lag)
        .execute(pool)
        .await
        .expect("insert completion");
    }
    request_id
}

async fn intent_exists(pool: &PgPool, request_id: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM audit_call_intents WHERE request_id = $1)")
        .bind(request_id)
        .fetch_one(pool)
        .await
        .expect("intent lookup")
}

/// A pair straddling the cutoff by milliseconds: the intent just inside the
/// TTL, its completion later still. Both tables are pruned against ONE
/// cutoff, so the surviving intent keeps its completion and a reaper sweep
/// does not invent an `abandoned` row for a call that succeeded.
#[tokio::test]
async fn pruner_never_orphans_a_surviving_intent() {
    let _serial = SWEEPS.lock().await;
    let p = state_pool().await;
    let user = format!("integrity-prune-{}", Uuid::new_v4().simple());
    const TTL_DAYS: u32 = 400;
    let ttl_secs = f64::from(TTL_DAYS) * 86_400.0;

    // Kept: intent 2 s inside the TTL, completion 0.5 s after it.
    let kept = backdated_call(&p, &user, ttl_secs - 2.0, Some(0.5)).await;
    // Expired: both rows well past the TTL.
    let expired = backdated_call(&p, &user, ttl_secs + 60.0, Some(0.5)).await;

    pruner::run_once(&p, TTL_DAYS).await.expect("pruner runs");

    assert!(intent_exists(&p, &kept).await, "intent inside TTL kept");
    let kept_calls = calls_for_request(&p, &kept).await;
    assert_eq!(kept_calls.len(), 1, "completion kept: {kept_calls:?}");
    assert!(!intent_exists(&p, &expired).await, "expired intent pruned");
    assert!(calls_for_request(&p, &expired).await.is_empty());

    reaper::run_once(&p, Duration::from_secs(3600), &mut ReapCursor::default())
        .await
        .expect("reaper sweep runs");
    let kept_calls = calls_for_request(&p, &kept).await;
    assert_eq!(kept_calls.len(), 1, "no abandoned row: {kept_calls:?}");
    assert_eq!(kept_calls[0].0, "success");

    delete_audit_calls(&p, &user).await;
}

/// The cursor bounds each sweep from below: an intent older than one a
/// committed sweep already examined is not rescanned. A sweep that loses the
/// lock leaves the cursor where it was, and a fresh cursor (a restarted
/// replica) catches up on everything.
#[tokio::test]
async fn reaper_cursor_resumes_without_rescanning_or_skipping() {
    let _serial = SWEEPS.lock().await;
    let p = state_pool().await;
    let user = format!("integrity-reap-{}", Uuid::new_v4().simple());
    let grace = Duration::from_secs(3600);
    let mut cursor = ReapCursor::default();

    let first = backdated_call(&p, &user, 2.0 * 3600.0, None).await;
    let reaped = reaper::run_once(&p, grace, &mut cursor)
        .await
        .expect("first sweep runs");
    assert!(reaped.is_some_and(|n| n >= 1), "{reaped:?}");
    assert_eq!(calls_for_request(&p, &first).await[0].0, "abandoned");
    assert_ne!(cursor, ReapCursor::default(), "cursor advanced");

    // Older than the cursor: a settled range, not rescanned.
    let behind = backdated_call(&p, &user, 3.0 * 3600.0, None).await;
    reaper::run_once(&p, grace, &mut cursor)
        .await
        .expect("second sweep runs");
    assert!(calls_for_request(&p, &behind).await.is_empty());

    // A peer holds the lock: no batch runs and the cursor stays put.
    let mut peer = p.begin().await.expect("peer tx");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(REAPER_LOCK_KEY)
        .execute(&mut *peer)
        .await
        .expect("peer takes the reaper lock");
    let before = cursor.clone();
    let contended = reaper::run_once(&p, grace, &mut cursor)
        .await
        .expect("contended sweep returns");
    assert_eq!(contended, None);
    assert_eq!(cursor, before, "a sweep that ran no batch keeps its cursor");
    peer.rollback().await.expect("peer releases the lock");

    // A newer aged intent is past the cursor and is reaped.
    let ahead = backdated_call(&p, &user, 1800.0, None).await;
    reaper::run_once(&p, Duration::from_secs(900), &mut cursor)
        .await
        .expect("third sweep runs");
    assert_eq!(calls_for_request(&p, &ahead).await[0].0, "abandoned");

    // A restarted replica starts from the oldest intent and settles the rest.
    reaper::run_once(&p, grace, &mut ReapCursor::default())
        .await
        .expect("fresh-cursor sweep runs");
    assert_eq!(calls_for_request(&p, &behind).await[0].0, "abandoned");
    assert_eq!(calls_for_request(&p, &first).await.len(), 1, "never twice");

    delete_audit_calls(&p, &user).await;
}

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "integrity@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
        kind: IdentityKind::Sso,
    }
}

/// Commit an intent with `access`, then drop the dispatch mid-work (client
/// disconnect) and drain: the `cancelled` row's message.
async fn cancelled_message_after_drop(access: Access) -> Option<String> {
    let p = state_pool().await;
    let user = format!("integrity-drop-{}", Uuid::new_v4().simple());
    let request_id = Uuid::new_v4();
    audit::intent::record(
        &p,
        &CallIntent {
            request_id,
            user_sub: &user,
            user_email: "integrity@example.com",
            tool: "run_query",
            server: "prod",
            database: "app",
            db_type: Some("postgres"),
            access,
            sql: Some("UPDATE t SET x = 1"),
            reason: None,
            upstream_actor: None,
            upstream_run_id: None,
        },
    )
    .await
    .expect("intent commits");

    let sinks = Arc::new(DispatchSinks::new(&[]));
    let armed = Arc::new(Notify::new());
    let task = {
        let (p, user, sinks, armed) = (p.clone(), user.clone(), sinks.clone(), armed.clone());
        tokio::spawn(async move {
            let work = async move {
                armed.notify_one();
                std::future::pending::<Outcome>().await
            };
            let ctx = RequestContext {
                ip: None,
                agent_client: None,
                request_id,
                upstream: Upstream::default(),
            };
            let header = AuditHeader {
                tool: "run_query",
                server: Some("prod"),
                database: Some("app"),
                sql: Some("UPDATE t SET x = 1"),
                reason: None,
                db_type: Some("postgres"),
            };
            audit_dispatch(
                Value::from(1),
                &identity(&user),
                &ctx,
                header,
                sinks.store(&p),
                work,
            )
            .await
        })
    };
    armed.notified().await;
    task.abort();
    assert!(task.await.err().is_some_and(|e| e.is_cancelled()));
    sinks
        .tasks
        .drain(Duration::from_secs(10))
        .await
        .expect("fallback write finishes inside the bound");

    let row = find_audit(&p, &user, "run_query")
        .await
        .expect("cancelled row is audited");
    assert_eq!(row.outcome, "cancelled");
    delete_audit_calls(&p, &user).await;
    row.error_message
}

/// A write dropped mid-work may have been dropped mid-commit: its
/// `cancelled` row says so. A read's does not.
#[tokio::test]
async fn dropped_write_is_audited_as_possibly_committed() {
    let write = cancelled_message_after_drop(Access::ReadWrite)
        .await
        .unwrap_or_default();
    assert!(write.contains(WRITE_MAY_HAVE_COMMITTED), "{write}");

    let read = cancelled_message_after_drop(Access::ReadOnly)
        .await
        .unwrap_or_default();
    assert!(!read.contains(WRITE_MAY_HAVE_COMMITTED), "{read}");
}
