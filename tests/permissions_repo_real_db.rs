//! Real-DB integration tests for [`PgPermissionsRepo`] (issue #48).
//!
//! Boots against the dev state DB (`bin/dev up`). Each test uses a unique
//! `user_sub` / server prefix so concurrent runs don't collide, and cleans up
//! its own rows so the suite stays idempotent.
//!
//! No mocking — CLAUDE.md forbids it on the query path. The XOR enforcement
//! test asserts the database CHECK still blocks raw-SQL bypasses; the typed
//! `GrantTarget` enum is the in-process guard rail above it.

use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::{
    DbType, GrantAction, GrantTarget, PermissionsRepo, pg::PgPermissionsRepo,
};
use sqlx::PgPool;
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

fn fresh_sub(tag: &str) -> String {
    format!("{tag}-{}", Uuid::new_v4().simple())
}

async fn cleanup_user(pool: &PgPool, user_sub: &str) {
    // Hard-delete rather than soft — the partial unique index lets a soft
    // delete linger and bloat the table across test reruns.
    sqlx::query(
        "DELETE FROM permissions_grants \
         WHERE user_id IN (SELECT id FROM permissions_users WHERE user_sub = $1)",
    )
    .bind(user_sub)
    .execute(pool)
    .await
    .expect("cleanup grants");
    sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(user_sub)
        .execute(pool)
        .await
        .expect("cleanup users");
}

async fn cleanup_database(pool: &PgPool, server: &str) {
    sqlx::query(
        "DELETE FROM permissions_grants \
         WHERE database_id IN (SELECT id FROM permissions_databases WHERE server = $1)",
    )
    .bind(server)
    .execute(pool)
    .await
    .expect("cleanup grants by db");
    sqlx::query("DELETE FROM permissions_databases WHERE server = $1")
        .bind(server)
        .execute(pool)
        .await
        .expect("cleanup databases");
}

#[tokio::test]
async fn upsert_user_creates_and_then_refreshes_email_and_groups() {
    let p = pool().await;
    let sub = fresh_sub("upsert");
    let repo = PgPermissionsRepo::new(p.clone());

    let first = repo
        .upsert_user(&sub, "a@example.com", &["devs".into()])
        .await
        .expect("first upsert");
    assert_eq!(first.user_email, "a@example.com");
    assert_eq!(first.groups, vec!["devs".to_string()]);

    let second = repo
        .upsert_user(&sub, "b@example.com", &["devs".into(), "cto".into()])
        .await
        .expect("second upsert");
    assert_eq!(second.id, first.id, "same sub must round-trip same row");
    assert_eq!(second.user_email, "b@example.com");
    assert_eq!(second.groups, vec!["devs".to_string(), "cto".to_string()]);
    assert!(second.updated_at >= first.updated_at);

    cleanup_user(&p, &sub).await;
}

#[tokio::test]
async fn get_user_by_sub_skips_soft_deleted() {
    let p = pool().await;
    let sub = fresh_sub("getsoft");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo
        .upsert_user(&sub, "x@example.com", &[])
        .await
        .expect("create");
    assert!(
        repo.get_user_by_sub(&sub).await.expect("get").is_some(),
        "live user should be found"
    );
    let deleted = repo.soft_delete_user(user.id).await.expect("delete");
    assert!(deleted, "delete should hit one row");
    assert!(
        repo.get_user_by_sub(&sub).await.expect("get").is_none(),
        "soft-deleted user must not surface"
    );
    // Second delete is a no-op (row already deleted).
    assert!(
        !repo.soft_delete_user(user.id).await.expect("redelete"),
        "second delete should affect 0 rows"
    );

    cleanup_user(&p, &sub).await;
}

#[tokio::test]
async fn database_crud_and_list_filters_soft_deleted() {
    let p = pool().await;
    let server = fresh_sub("dbcrud-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let pg_db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .expect("create pg");
    let mysql_db = repo
        .create_database(&server, "warehouse", DbType::Mysql)
        .await
        .expect("create mysql");
    assert_eq!(pg_db.db_type, DbType::Postgres);
    assert_eq!(mysql_db.db_type, DbType::Mysql);

    let listed = repo.list_databases().await.expect("list");
    assert!(listed.iter().any(|d| d.id == pg_db.id));
    assert!(listed.iter().any(|d| d.id == mysql_db.id));

    assert!(repo.soft_delete_database(pg_db.id).await.expect("del"));
    let after = repo.list_databases().await.expect("list2");
    assert!(
        !after.iter().any(|d| d.id == pg_db.id),
        "soft-deleted db must drop from list"
    );
    assert!(
        repo.get_database(pg_db.id).await.expect("get").is_none(),
        "soft-deleted db must not be fetchable"
    );

    cleanup_database(&p, &server).await;
}

#[tokio::test]
async fn create_specific_grant_round_trips() {
    let p = pool().await;
    let sub = fresh_sub("specific");
    let server = fresh_sub("specific-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    let grant = repo
        .create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            serde_json::json!({ "row_limit": 1000 }),
        )
        .await
        .expect("create grant");

    assert_eq!(grant.action, GrantAction::QueryRead);
    assert_eq!(grant.target, GrantTarget::Specific { database_id: db.id });
    let listed = repo.list_grants_for_user(user.id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, grant.id);

    cleanup_user(&p, &sub).await;
    cleanup_database(&p, &server).await;
}

#[tokio::test]
async fn create_wildcard_grant_round_trips() {
    let p = pool().await;
    let sub = fresh_sub("wildcard");
    let server = fresh_sub("wc-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "w@example.com", &[]).await.unwrap();
    let grant = repo
        .create_grant(
            user.id,
            GrantTarget::Wildcard {
                server: server.clone(),
            },
            GrantAction::SchemaRead,
            serde_json::json!({}),
        )
        .await
        .expect("wildcard grant");

    assert_eq!(
        grant.target,
        GrantTarget::Wildcard {
            server: server.clone()
        }
    );
    let listed = repo.list_grants_for_user(user.id).await.unwrap();
    assert_eq!(listed.len(), 1);

    cleanup_user(&p, &sub).await;
}

#[tokio::test]
async fn revoked_grants_drop_from_user_listing() {
    let p = pool().await;
    let sub = fresh_sub("revoke");
    let server = fresh_sub("revoke-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "r@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    let grant = repo
        .create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            serde_json::json!({}),
        )
        .await
        .unwrap();

    assert_eq!(repo.list_grants_for_user(user.id).await.unwrap().len(), 1);
    assert!(repo.revoke_grant(grant.id).await.unwrap());
    assert!(
        repo.list_grants_for_user(user.id).await.unwrap().is_empty(),
        "revoked grant must not surface to resolver"
    );
    // Idempotent revoke.
    assert!(!repo.revoke_grant(grant.id).await.unwrap());

    cleanup_user(&p, &sub).await;
    cleanup_database(&p, &server).await;
}

/// The DB CHECK is the safety net behind the typed `GrantTarget` enum. A raw
/// INSERT that violates the XOR must still be rejected by Postgres — that's
/// what protects us if someone bypasses the repo (manual migration, ad-hoc
/// admin SQL).
#[tokio::test]
async fn raw_insert_with_both_specific_and_wildcard_is_rejected_by_check() {
    let p = pool().await;
    let sub = fresh_sub("xorcheck");
    let server = fresh_sub("xor-server");

    let repo = PgPermissionsRepo::new(p.clone());
    let user = repo.upsert_user(&sub, "x@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();

    // Both database_id AND wildcard=true → must violate
    // permissions_grants_target_xor_wildcard_check.
    let err = sqlx::query(
        "INSERT INTO permissions_grants \
         (user_id, server, database_id, db_name_wildcard, action) \
         VALUES ($1, $2, $3, true, 'query_read')",
    )
    .bind(user.id)
    .bind(&server)
    .bind(db.id)
    .execute(&p)
    .await
    .expect_err("CHECK must reject the contradictory row");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("permissions_grants_target_xor_wildcard_check"),
        "expected XOR check violation, got: {msg}"
    );

    cleanup_user(&p, &sub).await;
    cleanup_database(&p, &server).await;
}
