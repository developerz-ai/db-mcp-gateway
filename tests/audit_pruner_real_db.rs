//! Real-DB test for `audit::pruner::run_once`: insert one ancient row + one
//! fresh row + assert only the ancient one is deleted.
//!
//! Uses a per-test `user_sub` so concurrent runs (and any dev rows from
//! other tests) don't interfere with the assertions.

use db_mcp_gateway::audit::{self, AuditRow};
use db_mcp_gateway::state;
use sqlx::Row;
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn pool() -> sqlx::PgPool {
    state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

fn audit_row(user_sub: &str, request_id: &str) -> AuditRow {
    AuditRow {
        request_id: request_id.to_string(),
        user_sub: user_sub.to_string(),
        user_email: "pruner-test@example.com".to_string(),
        groups: vec!["test".to_string()],
        tool: "list_servers".to_string(),
        server: None,
        database: None,
        sql: None,
        reason: None,
        outcome: "success".to_string(),
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
    }
}

/// The acceptance test: an old row gets deleted; a fresh one stays.
#[tokio::test]
async fn pruner_deletes_only_rows_older_than_ttl() {
    let p = pool().await;
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
    sqlx::query("DELETE FROM audit_calls WHERE user_sub = $1")
        .bind(&user)
        .execute(&p)
        .await
        .unwrap();
}

// Tempting to add a `ttl=0 deletes everything` sanity test, but
// `pruner::run_once` doesn't scope by user — a parallel run would
// indiscriminately wipe any audit rows another test was depending on.
// The acceptance above already proves the SQL is shaped correctly.
