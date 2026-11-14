//! The intent row carries the statement and reason (migration 0018), so the
//! reaper's `abandoned` row says what may have run. Its own binary: a reaper
//! sweep is global, and the other integrity tests assert on sweeps too.

mod common;

use std::time::Duration;

use common::cleanup::delete_audit_calls;
use common::env::state_pool;
use db_mcp_gateway::audit::reaper::{self, ReapCursor};
use db_mcp_gateway::audit::{self, CallIntent};
use db_mcp_gateway::exec::Access;
use uuid::Uuid;

/// An intent carries the statement and reason, so the `abandoned` row of a
/// write that may have committed still says what it was.
#[tokio::test]
async fn abandoned_row_carries_the_intent_statement_and_reason() {
    let p = state_pool().await;
    let user = format!("integrity-stmt-{}", Uuid::new_v4().simple());
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
            access: Access::ReadWrite,
            sql: Some("DELETE FROM orders WHERE id = 7"),
            reason: Some("OPS-9 cleanup"),
            upstream_actor: None,
            upstream_run_id: None,
        },
    )
    .await
    .expect("intent commits");
    sqlx::query(
        "UPDATE audit_call_intents SET occurred_at = now() - interval '2 hours' \
         WHERE request_id = $1",
    )
    .bind(request_id.to_string())
    .execute(&p)
    .await
    .expect("backdate intent");

    reaper::run_once(&p, Duration::from_secs(3600), &mut ReapCursor::default())
        .await
        .expect("sweep runs");
    let (outcome, sql, reason): (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT outcome, sql, reason FROM audit_calls WHERE request_id = $1")
            .bind(request_id.to_string())
            .fetch_one(&p)
            .await
            .expect("abandoned row written");
    assert_eq!(outcome, "abandoned");
    assert_eq!(sql.as_deref(), Some("DELETE FROM orders WHERE id = 7"));
    assert_eq!(reason.as_deref(), Some("OPS-9 cleanup"));

    delete_audit_calls(&p, &user).await;
}
