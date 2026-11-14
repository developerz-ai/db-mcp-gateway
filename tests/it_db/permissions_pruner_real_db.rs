//! Real-DB test: the retention pruner hard-deletes permissions rows that were
//! soft-deleted (users, databases) or revoked (grants) longer than the TTL
//! ago — children first, never a live row, never a parent a grant still
//! references.

use crate::common::env::state_pool;
use db_mcp_gateway::audit;
use sqlx::PgPool;
use uuid::Uuid;

async fn user(p: &PgPool, sub: &str, deleted_days_ago: Option<i32>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO permissions_users (user_sub, user_email, created_at, deleted_at) \
         VALUES ($1, 'prune@example.com', now() - interval '400 days', \
                 now() - make_interval(days => $2)) RETURNING id",
    )
    .bind(sub)
    .bind(deleted_days_ago)
    .fetch_one(p)
    .await
    .expect("seed user")
}

async fn database(p: &PgPool, name: &str, deleted_days_ago: Option<i32>) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO permissions_databases (server, db_name, db_type, created_at, deleted_at) \
         VALUES ('prune-srv', $1, 'postgres', now() - interval '400 days', \
                 now() - make_interval(days => $2)) RETURNING id",
    )
    .bind(name)
    .bind(deleted_days_ago)
    .fetch_one(p)
    .await
    .expect("seed database")
}

async fn grant(
    p: &PgPool,
    user_id: Uuid,
    database_id: Uuid,
    revoked_days_ago: Option<i32>,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO permissions_grants (user_id, database_id, action, created_at, revoked_at) \
         VALUES ($1, $2, 'query_read', now() - interval '400 days', \
                 now() - make_interval(days => $3)) RETURNING id",
    )
    .bind(user_id)
    .bind(database_id)
    .bind(revoked_days_ago)
    .fetch_one(p)
    .await
    .expect("seed grant")
}

async fn exists(p: &PgPool, table: &str, id: Uuid) -> bool {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1)"
    ))
    .bind(id)
    .fetch_one(p)
    .await
    .expect("exists")
}

#[tokio::test]
#[serial_test::serial(world)]
async fn pruner_hard_deletes_expired_soft_deleted_permissions_rows() {
    let p = state_pool().await;
    let tag = Uuid::new_v4().simple().to_string();

    // Expired: user + database deleted 100 days ago, their grant revoked then.
    let old_user = user(&p, &format!("prune-old-{tag}"), Some(100)).await;
    let old_db = database(&p, &format!("old-{tag}"), Some(100)).await;
    let old_grant = grant(&p, old_user, old_db, Some(100)).await;
    // Inside the window: deleted / revoked 89 days ago.
    let edge_user = user(&p, &format!("prune-edge-{tag}"), Some(89)).await;
    let edge_db = database(&p, &format!("edge-{tag}"), Some(89)).await;
    let edge_grant = grant(&p, edge_user, edge_db, Some(89)).await;
    // Live rows, created long ago.
    let live_user = user(&p, &format!("prune-live-{tag}"), None).await;
    let live_db = database(&p, &format!("live-{tag}"), None).await;
    let live_grant = grant(&p, live_user, live_db, None).await;
    // Anomaly: expired soft-deleted parents a live grant still references.
    let orphan_user = user(&p, &format!("prune-orphan-{tag}"), Some(100)).await;
    let orphan_grant = grant(&p, orphan_user, live_db, None).await;
    let orphan_db = database(&p, &format!("orphan-{tag}"), Some(100)).await;
    let orphan_db_grant = grant(&p, live_user, orphan_db, None).await;

    audit::pruner::run_once(&p, 90).await.expect("pruner runs");

    for (table, id) in [
        ("permissions_grants", old_grant),
        ("permissions_databases", old_db),
        ("permissions_users", old_user),
    ] {
        assert!(!exists(&p, table, id).await, "expired {table} row kept");
    }
    for (table, id) in [
        ("permissions_grants", edge_grant),
        ("permissions_databases", edge_db),
        ("permissions_users", edge_user),
        ("permissions_grants", live_grant),
        ("permissions_databases", live_db),
        ("permissions_users", live_user),
        ("permissions_grants", orphan_grant),
        ("permissions_users", orphan_user),
        ("permissions_grants", orphan_db_grant),
        ("permissions_databases", orphan_db),
    ] {
        assert!(exists(&p, table, id).await, "{table} row {id} deleted");
    }

    for g in [edge_grant, live_grant, orphan_grant, orphan_db_grant] {
        sqlx::query("DELETE FROM permissions_grants WHERE id = $1")
            .bind(g)
            .execute(&p)
            .await
            .expect("cleanup grant");
    }
    for d in [edge_db, live_db, orphan_db] {
        sqlx::query("DELETE FROM permissions_databases WHERE id = $1")
            .bind(d)
            .execute(&p)
            .await
            .expect("cleanup database");
    }
    for u in [edge_user, live_user, orphan_user] {
        sqlx::query("DELETE FROM permissions_users WHERE id = $1")
            .bind(u)
            .execute(&p)
            .await
            .expect("cleanup user");
    }
}
