//! Real-DB integration tests for the permissions-audit writer (#51).
//!
//! Boots against the dev state DB (`bin/dev up`). Each test uses a unique
//! `target_id` so concurrent runs don't collide, and cleans up its own
//! rows so the suite stays idempotent.
//!
//! Acceptance per #51:
//!  - successful write produces a readable row (every field round-trips)
//!  - audit-write failure surfaces a typed `Err` — the admin endpoint (#52+)
//!    is then responsible for rolling back the data change
//!
//! The "audit failure rolls back the data change" *integration* test lives
//! with the admin endpoints — there's no caller to roll back here. What we
//! prove now is that the writer's error is non-swallowed and typed.

use db_mcp_gateway::audit::permissions::{
    self, PermissionsAuditAction, PermissionsAuditError, PermissionsAuditRow,
    PermissionsAuditTargetType,
};
use db_mcp_gateway::state;
use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;

fn state_db_url() -> String {
    std::env::var("STATE_DB_URL").unwrap_or_else(|_| {
        "postgres://gateway:gateway-dev-only@localhost:5433/gateway".to_string()
    })
}

async fn pool() -> PgPool {
    state::connect(&state_db_url(), 5)
        .await
        .expect("state DB up (run `bin/dev up`)")
}

async fn cleanup(pool: &PgPool, target_id: Uuid) {
    sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(target_id)
        .execute(pool)
        .await
        .expect("cleanup audit rows");
}

fn create_row(actor_id: Uuid, target_id: Uuid, request_id: &str) -> PermissionsAuditRow {
    PermissionsAuditRow {
        actor_id,
        actor_email: "admin@example.com".to_string(),
        action: PermissionsAuditAction::Create,
        target_type: PermissionsAuditTargetType::User,
        target_id,
        before: None,
        after: Some(json!({
            "id": target_id,
            "user_sub": "sso-sub-123",
            "user_email": "new@example.com",
            "groups": ["devs"],
        })),
        request_id: request_id.to_string(),
    }
}

#[tokio::test]
async fn create_row_round_trips_through_writer_and_reader() {
    let p = pool().await;
    let actor = Uuid::new_v4();
    let target = Uuid::new_v4();
    let row = create_row(actor, target, "req-create");

    permissions::log(&p, &row).await.expect("write succeeds");

    let (read_back, _ts) =
        permissions::latest_for_target(&p, PermissionsAuditTargetType::User, target)
            .await
            .expect("readback query")
            .expect("row exists");
    assert_eq!(read_back.actor_id, actor);
    assert_eq!(read_back.actor_email, "admin@example.com");
    assert_eq!(read_back.action, PermissionsAuditAction::Create);
    assert_eq!(read_back.target_type, PermissionsAuditTargetType::User);
    assert_eq!(read_back.target_id, target);
    assert!(
        read_back.before.is_none(),
        "create row must have before=null"
    );
    assert_eq!(read_back.after, row.after);
    assert_eq!(read_back.request_id, "req-create");

    cleanup(&p, target).await;
}

#[tokio::test]
async fn delete_row_omits_after_payload() {
    let p = pool().await;
    let actor = Uuid::new_v4();
    let target = Uuid::new_v4();
    let row = PermissionsAuditRow {
        actor_id: actor,
        actor_email: "admin@example.com".to_string(),
        action: PermissionsAuditAction::Delete,
        target_type: PermissionsAuditTargetType::Grant,
        target_id: target,
        before: Some(json!({"id": target, "action": "query_read"})),
        after: None,
        request_id: "req-delete".to_string(),
    };
    permissions::log(&p, &row).await.expect("write succeeds");

    let (read_back, _ts) =
        permissions::latest_for_target(&p, PermissionsAuditTargetType::Grant, target)
            .await
            .expect("readback")
            .expect("row exists");
    assert_eq!(read_back.action, PermissionsAuditAction::Delete);
    assert!(read_back.after.is_none(), "delete row must have after=null");
    assert!(read_back.before.is_some());

    cleanup(&p, target).await;
}

#[tokio::test]
async fn update_row_records_both_before_and_after() {
    // Mirrors the most common admin path: rename a database, change a grant's
    // constraints. Both halves of the diff must survive.
    let p = pool().await;
    let actor = Uuid::new_v4();
    let target = Uuid::new_v4();
    let row = PermissionsAuditRow {
        actor_id: actor,
        actor_email: "admin@example.com".to_string(),
        action: PermissionsAuditAction::Update,
        target_type: PermissionsAuditTargetType::Database,
        target_id: target,
        before: Some(json!({"id": target, "db_name": "old_name"})),
        after: Some(json!({"id": target, "db_name": "new_name"})),
        request_id: "req-update".to_string(),
    };
    permissions::log(&p, &row).await.expect("write succeeds");

    let (read_back, _) =
        permissions::latest_for_target(&p, PermissionsAuditTargetType::Database, target)
            .await
            .expect("readback")
            .expect("row exists");
    assert_eq!(read_back.before, row.before);
    assert_eq!(read_back.after, row.after);

    cleanup(&p, target).await;
}

#[tokio::test]
async fn ts_defaults_to_server_time_and_is_recent() {
    let p = pool().await;
    let actor = Uuid::new_v4();
    let target = Uuid::new_v4();
    permissions::log(&p, &create_row(actor, target, "req-ts"))
        .await
        .expect("write succeeds");

    let (_, ts) = permissions::latest_for_target(&p, PermissionsAuditTargetType::User, target)
        .await
        .expect("readback")
        .expect("row exists");
    let age = chrono::Utc::now().signed_duration_since(ts);
    // Generous bound; the test runner can be slow on CI but never minutes.
    assert!(
        age.num_seconds().abs() < 60,
        "audit ts should be within ~60s of now, got {age}"
    );

    cleanup(&p, target).await;
}

#[tokio::test]
async fn writer_returns_typed_error_when_pool_is_dead() {
    // The acceptance is "audit-write failure surfaces a 5xx and rolls back"
    // — the rollback half lives with the admin endpoint (#52). What's
    // proven here is the first half: an unreachable DB yields a typed
    // `PermissionsAuditError::Write(_)` that the caller can propagate
    // instead of a panic or a silently-swallowed result.
    let dead_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(50))
        .connect_lazy("postgres://nope:nope@127.0.0.1:1/nope")
        .expect("lazy connect builds");

    let row = create_row(Uuid::new_v4(), Uuid::new_v4(), "req-fail");
    let err = permissions::log(&dead_pool, &row)
        .await
        .expect_err("dead pool must fail the write");
    assert!(
        matches!(err, PermissionsAuditError::Write(_)),
        "expected Write variant, got {err:?}"
    );
}

#[tokio::test]
async fn check_constraint_rejects_unknown_action_via_raw_insert() {
    // The typed `PermissionsAuditAction` is the in-process guard, but the DB
    // CHECK is what protects us from raw-SQL bypasses (manual migrations,
    // ad-hoc admin SQL). Confirm Postgres still blocks an out-of-set value.
    let p = pool().await;
    let target = Uuid::new_v4();
    let err = sqlx::query(
        "INSERT INTO permissions_audit \
         (actor_id, actor_email, action, target_type, target_id, request_id) \
         VALUES ($1, 'admin@example.com', 'rotate', 'user', $1, 'req-x')",
    )
    .bind(target)
    .execute(&p)
    .await
    .expect_err("CHECK must reject `rotate`");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("permissions_audit_action_check"),
        "expected action CHECK violation, got {msg}"
    );
}

#[tokio::test]
async fn check_constraint_rejects_empty_actor_email() {
    // Empty actor_email bypasses the audit identity contract. The DB CHECK
    // prevents this even if the writer mistakenly passes an empty string.
    let p = pool().await;
    let target = Uuid::new_v4();
    let err = sqlx::query(
        "INSERT INTO permissions_audit \
         (actor_id, actor_email, action, target_type, target_id, before, after, request_id) \
         VALUES ($1, '', 'create', 'user', $1, NULL, '{}'::jsonb, 'req-x')",
    )
    .bind(target)
    .execute(&p)
    .await
    .expect_err("CHECK must reject empty actor_email");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("permissions_audit_actor_email_not_empty"),
        "expected actor_email NOT-EMPTY CHECK violation, got {msg}"
    );
}

#[tokio::test]
async fn check_constraint_rejects_empty_request_id() {
    // Empty request_id breaks the per-request tracing contract. The DB CHECK
    // prevents this even if the writer mistakenly passes an empty string.
    let p = pool().await;
    let target = Uuid::new_v4();
    let err = sqlx::query(
        "INSERT INTO permissions_audit \
         (actor_id, actor_email, action, target_type, target_id, before, after, request_id) \
         VALUES ($1, 'admin@example.com', 'create', 'user', $1, NULL, '{}'::jsonb, '')",
    )
    .bind(target)
    .execute(&p)
    .await
    .expect_err("CHECK must reject empty request_id");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("permissions_audit_request_id_not_empty"),
        "expected request_id NOT-EMPTY CHECK violation, got {msg}"
    );
}

#[tokio::test]
async fn log_accepts_transaction_executor_and_respects_rollback() {
    // Verifies the new Executor trait bound allows transactions.
    // A rolled-back transaction must not persist the audit row.
    let p = pool().await;
    let actor = Uuid::new_v4();
    let target = Uuid::new_v4();
    let row = create_row(actor, target, "req-tx");

    let mut tx = p.begin().await.expect("begin tx");
    permissions::log(&mut *tx, &row)
        .await
        .expect("audit write in tx");
    tx.rollback().await.expect("rollback");

    let read_back = permissions::latest_for_target(&p, PermissionsAuditTargetType::User, target)
        .await
        .expect("readback");
    assert!(
        read_back.is_none(),
        "rolled-back tx must not persist audit row"
    );
}
