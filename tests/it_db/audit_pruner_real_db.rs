//! Real-DB test for `audit::pruner::run_once`: insert one ancient row + one
//! fresh row + assert only the ancient one is deleted.
//!
//! Uses a per-test `user_sub` so concurrent runs (and any dev rows from
//! other tests) don't interfere with the assertions.

use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use db_mcp_gateway::audit::{self, AuditRow, OutcomeCode};
use sqlx::Row;
use uuid::Uuid;

fn audit_row(user_sub: &str, request_id: &str) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: request_id.to_string(),
        user_sub: user_sub.to_string(),
        user_email: "pruner-test@example.com".to_string(),
        groups: vec!["test".to_string()],
        tool: "list_servers".to_string(),
        server: None,
        database: None,
        sql: None,
        reason: None,
        outcome: OutcomeCode::Success,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: None,
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    }
}

/// The acceptance test: an old row gets deleted; a fresh one stays.
#[tokio::test]
#[serial_test::serial(world)]
async fn pruner_deletes_only_rows_older_than_ttl() {
    let p = state_pool().await;
    let user = format!("pruner-test-{}", Uuid::new_v4().simple());

    // Write the fresh row through the real audit writer (occurred_at defaults
    // to now()).
    audit::log(&p, &audit_row(&user, "fresh"))
        .await
        .expect("write fresh row");

    // Backdate one row to 100 days ago. We can't override `occurred_at`
    // through `audit::log` by design — operators write rows for *now*. For
    // the test, a direct UPDATE on this user's freshly-inserted row would
    // also work, but inserting a separate ancient row is clearer.
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, tool, outcome, occurred_at) \
         VALUES ($1, 'ancient', $2, 'pruner-test@example.com', 'list_servers', \
                 'success', now() - interval '100 days')",
    )
    .bind(Uuid::new_v4())
    .bind(&user)
    .execute(&p)
    .await
    .expect("insert ancient row");

    // Confirm both rows are there before pruning.
    let before: i64 = sqlx::query("SELECT count(*) FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .fetch_one(&p)
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, 2, "setup should leave 2 rows for this user");

    // Prune at the 90-day TTL — ancient (100 days old) goes, fresh stays.
    let deleted = audit::pruner::run_once(&p, 90).await.expect("pruner runs");
    assert!(deleted >= 1, "expected ≥1 deletion, got {deleted}");

    let after: i64 = sqlx::query("SELECT count(*) FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .fetch_one(&p)
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, 1, "only the fresh row should remain");

    let surviving_request_id: String =
        sqlx::query("SELECT request_id FROM audit_calls WHERE user_sub = $1")
            .bind(&user)
            .fetch_one(&p)
            .await
            .unwrap()
            .get(0);
    assert_eq!(surviving_request_id, "fresh");

    // Cleanup so this test stays idempotent across reruns.
    delete_audit_calls(&p, &user).await;
}

// Tempting to add a `ttl=0 deletes everything` sanity test, but
// `pruner::run_once` doesn't scope by user — a parallel run would
// indiscriminately wipe any audit rows another test was depending on.
// The acceptance above already proves the SQL is shaped correctly.

/// A backlog larger than one batch is drained in one run, intents included,
/// while rows inside the TTL survive.
#[tokio::test]
#[serial_test::serial(world)]
async fn pruner_drains_a_backlog_larger_than_one_batch() {
    let p = state_pool().await;
    let user = format!("pruner-batch-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, tool, outcome, occurred_at) \
         SELECT gen_random_uuid(), gen_random_uuid()::text, $1, 'p@example.com', \
                'list_servers', 'success', now() - interval '200 days' \
         FROM generate_series(1, 5003)",
    )
    .bind(&user)
    .execute(&p)
    .await
    .expect("seed old calls");
    sqlx::query(
        "INSERT INTO audit_call_intents \
         (request_id, occurred_at, user_sub, user_email, tool, server_name, database_name, access) \
         VALUES (gen_random_uuid()::text, now() - interval '200 days', $1, 'p@example.com', \
                 'run_query', 'prod', 'app', 'read'), \
                (gen_random_uuid()::text, now(), $1, 'p@example.com', \
                 'run_query', 'prod', 'app', 'read')",
    )
    .bind(&user)
    .execute(&p)
    .await
    .expect("seed intents");

    let deleted = audit::pruner::run_once(&p, 90).await.expect("pruner runs");
    assert!(deleted >= 5004, "expected the whole backlog, got {deleted}");

    let calls_left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_calls WHERE user_sub = $1")
            .bind(&user)
            .fetch_one(&p)
            .await
            .unwrap();
    let intents_left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_call_intents WHERE user_sub = $1")
            .bind(&user)
            .fetch_one(&p)
            .await
            .unwrap();
    assert_eq!(calls_left, 0);
    assert_eq!(intents_left, 1, "the fresh intent survives");

    sqlx::query("DELETE FROM audit_call_intents WHERE user_sub = $1")
        .bind(&user)
        .execute(&p)
        .await
        .unwrap();
}
