//! Two-phase audit against the real state DB (plan 101, slice 04):
//!
//! - an intent with no completion row is reaped as `abandoned` once past the
//!   grace, and one with a completion is left alone;
//! - a dispatch dropped mid-work has its `cancelled` row on disk once the
//!   detached set is drained — no polling, the drain is the guarantee;
//! - when the completion write fails, the row the fallback lands carries the
//!   code the client saw (`audit_unavailable`), not the tool's own outcome.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::audit::{DispatchSinks, calls_for_request, find_audit, find_intent};
use common::cleanup::delete_audit_calls;
use common::env::{state_db_url, state_pool};
use db_mcp_gateway::audit::{self, CallIntent};
use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::exec::Access;
use db_mcp_gateway::tools::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, success_outcome,
};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Notify;
use uuid::Uuid;

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "two-phase@example.com".to_string(),
        groups: vec!["test".to_string()],
        issued_at: chrono::Utc::now(),
        kind: db_mcp_gateway::auth::IdentityKind::Sso,
    }
}

fn header() -> AuditHeader<'static> {
    AuditHeader {
        tool: "run_query",
        server: Some("prod"),
        database: Some("app"),
        sql: Some("SELECT 1"),
        reason: None,
        db_type: Some("postgres"),
    }
}

fn intent<'a>(request_id: Uuid, user_sub: &'a str, access: Access) -> CallIntent<'a> {
    CallIntent {
        request_id,
        user_sub,
        user_email: "two-phase@example.com",
        tool: "run_query",
        server: "prod",
        database: "app",
        db_type: Some("postgres"),
        access,
    }
}

/// The gateway died between the target call and the completion row: only
/// the intent exists. The reaper must account for the call as `abandoned`,
/// naming whether it could have written.
#[tokio::test]
async fn intent_without_completion_is_reaped_as_abandoned() {
    let p = state_pool().await;
    let user = format!("two-phase-{}", Uuid::new_v4().simple());
    let orphan = Uuid::new_v4();
    let completed = Uuid::new_v4();

    // Inside the grace the intent may belong to a call still running.
    audit::intent::record(&p, &intent(orphan, &user, Access::ReadWrite))
        .await
        .expect("orphan intent commits");
    assert_eq!(
        find_intent(&p, &orphan.to_string()).await.as_deref(),
        Some("write")
    );
    audit::reaper::run_once(&p, audit::reaper::REAPER_GRACE)
        .await
        .expect("sweep inside the grace runs");
    assert!(calls_for_request(&p, &orphan.to_string()).await.is_empty());

    // Past the grace (zero here) it is abandoned; a completed one is not.
    audit::intent::record(&p, &intent(completed, &user, Access::ReadOnly))
        .await
        .expect("completed intent commits");
    let ctx = RequestContext {
        request_id: completed,
        ip: None,
        agent_client: None,
    };
    let sinks = DispatchSinks::new(&[]);
    let outcome = success_outcome(json!(1), "{}".into(), Some(1), Some(1), Some(false));
    audit_dispatch(
        json!(1),
        &identity(&user),
        &ctx,
        header(),
        sinks.store(&p),
        std::future::ready(outcome),
    )
    .await;

    let reaped = audit::reaper::run_once(&p, Duration::ZERO)
        .await
        .expect("reaper sweep runs");
    assert!(
        reaped.is_some_and(|n| n >= 1),
        "sweep wrote rows: {reaped:?}"
    );

    let orphan_rows = calls_for_request(&p, &orphan.to_string()).await;
    assert_eq!(orphan_rows.len(), 1, "{orphan_rows:?}");
    assert_eq!(orphan_rows[0].0, "abandoned");
    let message = orphan_rows[0].1.as_deref().unwrap_or_default();
    assert!(message.contains("access: write"), "{message}");

    let completed_rows = calls_for_request(&p, &completed.to_string()).await;
    assert_eq!(
        completed_rows.len(),
        1,
        "completion must not be reaped twice"
    );
    assert_eq!(completed_rows[0].0, "success");

    // A second sweep finds nothing new for these intents.
    audit::reaper::run_once(&p, Duration::ZERO)
        .await
        .expect("second sweep runs");
    assert_eq!(calls_for_request(&p, &orphan.to_string()).await.len(), 1);

    delete_audit_calls(&p, &user).await;
}

/// Abort mid-work, then drain: the `cancelled` row is committed by the time
/// `drain` returns. This is the shutdown contract — `main` drains instead of
/// letting the runtime drop the fallback write.
#[tokio::test]
async fn drain_completes_the_cancelled_row_of_an_aborted_dispatch() {
    let p = state_pool().await;
    let user = format!("two-phase-{}", Uuid::new_v4().simple());
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
                request_id: Uuid::new_v4(),
            };
            audit_dispatch(
                Value::from(1),
                &identity(&user),
                &ctx,
                header(),
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
        .expect("cancelled row is on disk when drain returns");
    assert_eq!(row.outcome, "cancelled");

    delete_audit_calls(&p, &user).await;
}

/// The completion write fails (the only connection of a one-connection pool
/// is held), the client gets `audit_unavailable`, and the fallback — run once
/// the connection frees — records `audit_unavailable` with the tool's own
/// outcome in `error_message`.
#[tokio::test]
async fn failed_completion_write_records_the_code_the_client_saw() {
    let reader = state_pool().await;
    let narrow = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(300))
        .connect(&state_db_url())
        .await
        .expect("one-connection pool");
    let user = format!("two-phase-{}", Uuid::new_v4().simple());
    let sinks = DispatchSinks::new(&[]);
    let ctx = RequestContext {
        request_id: Uuid::new_v4(),
        ip: None,
        agent_client: None,
    };
    let outcome = success_outcome(json!(9), "{}".into(), Some(3), Some(1), Some(false));

    let held = narrow.acquire().await.expect("hold the only connection");
    let response = audit_dispatch(
        json!(9),
        &identity(&user),
        &ctx,
        header(),
        sinks.store(&narrow),
        std::future::ready(outcome),
    )
    .await;
    drop(held);

    let body = serde_json::to_value(&response).expect("response serializes");
    assert_eq!(body["result"]["isError"], true, "{body}");
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    let payload: Value = serde_json::from_str(text).unwrap();
    assert_eq!(payload["code"], "audit_unavailable");
    // The error body carries the gateway id that keys the audit row, not the
    // client's JSON-RPC id (9).
    assert_eq!(payload["request_id"], ctx.request_id.to_string());

    sinks
        .tasks
        .drain(Duration::from_secs(10))
        .await
        .expect("fallback write finishes");
    let rows = calls_for_request(&reader, &ctx.request_id.to_string()).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, "audit_unavailable");
    assert_eq!(rows[0].1.as_deref(), Some("tool outcome success"));

    delete_audit_calls(&reader, &user).await;
}
