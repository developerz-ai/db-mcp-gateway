//! Direct tests for the pg permissions store's partial-update writes,
//! `tx_update_user` and `tx_update_grant` (plan 101 slice 13 step 11). The
//! admin e2e suites reach them only through HTTP; these pin the SQL
//! contract itself: `None` leaves a column, a soft-deleted / revoked row is
//! never resurrected, and a rolled-back transaction leaves nothing.
//!
//! The MySQL store has no update path to test: it is read-only-provisioned
//! (spec 12 §"Storage backends"), filled by the operator's own tooling.
//!
//! Requires the dev state DB (`bin/dev up`); run under the shared DB lock.

use crate::common::env::state_pool;
use db_mcp_gateway::state::permissions::pg::{PgPermissionsRepo, grants, users};
use db_mcp_gateway::state::permissions::{
    GrantAction, GrantTarget, PermissionsGrant, PermissionsRepo, PermissionsSeed, PermissionsUser,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn cleanup(pool: &PgPool, user_sub: &str) {
    for sql in [
        "DELETE FROM permissions_grants \
         WHERE user_id IN (SELECT id FROM permissions_users WHERE user_sub = $1)",
        "DELETE FROM permissions_users WHERE user_sub = $1",
    ] {
        sqlx::query(sql)
            .bind(user_sub)
            .execute(pool)
            .await
            .expect("cleanup");
    }
}

/// A fresh user with email `old@example.com` and groups `[a]`.
async fn seed_user(repo: &PgPermissionsRepo, tag: &str) -> PermissionsUser {
    let sub = format!("{tag}-{}", Uuid::new_v4().simple());
    repo.upsert_user(&sub, "old@example.com", &["a".to_string()])
        .await
        .expect("seed user")
}

/// A `query_read` wildcard grant on `prod` with `row_limit: 10`.
async fn seed_grant(repo: &PgPermissionsRepo, user_id: Uuid) -> PermissionsGrant {
    repo.create_grant(
        user_id,
        GrantTarget::Wildcard {
            server: "prod".to_string(),
        },
        GrantAction::QueryRead,
        json!({ "row_limit": 10 }),
    )
    .await
    .expect("seed grant")
}

async fn update_user(
    pool: &PgPool,
    id: Uuid,
    email: Option<&str>,
    groups: Option<&[String]>,
) -> Option<PermissionsUser> {
    let mut tx = pool.begin().await.expect("begin");
    let updated = users::tx_update_user(&mut tx, id, email, groups)
        .await
        .expect("update user");
    tx.commit().await.expect("commit");
    updated
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn update_user_changes_only_the_given_columns() {
    let pool = state_pool().await;
    let repo = PgPermissionsRepo::new(pool.clone());
    let user = seed_user(&repo, "tx-update-user").await;

    let emailed = update_user(&pool, user.id, Some("new@example.com"), None)
        .await
        .expect("live user updates");
    assert_eq!(emailed.user_email, "new@example.com");
    assert_eq!(emailed.groups, vec!["a".to_string()], "groups untouched");
    assert!(emailed.updated_at >= user.updated_at);

    let regrouped = update_user(&pool, user.id, None, Some(&["b".to_string()]))
        .await
        .expect("live user updates");
    assert_eq!(regrouped.user_email, "new@example.com", "email untouched");
    assert_eq!(regrouped.groups, vec!["b".to_string()]);

    let emptied = update_user(&pool, user.id, None, Some(&[]))
        .await
        .expect("live user updates");
    assert!(emptied.groups.is_empty(), "an empty list clears, not skips");

    cleanup(&pool, &user.user_sub).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn update_user_never_touches_a_missing_or_soft_deleted_user() {
    let pool = state_pool().await;
    let repo = PgPermissionsRepo::new(pool.clone());
    let user = seed_user(&repo, "tx-update-deleted").await;

    assert!(
        update_user(&pool, Uuid::new_v4(), Some("x@example.com"), None)
            .await
            .is_none()
    );
    assert!(repo.soft_delete_user(user.id).await.expect("soft delete"));
    assert!(
        update_user(&pool, user.id, Some("x@example.com"), None)
            .await
            .is_none(),
        "a soft-deleted user must stay deleted"
    );

    cleanup(&pool, &user.user_sub).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn rolled_back_user_update_leaves_the_row() {
    let pool = state_pool().await;
    let repo = PgPermissionsRepo::new(pool.clone());
    let user = seed_user(&repo, "tx-update-rollback").await;

    let mut tx = pool.begin().await.expect("begin");
    users::tx_update_user(&mut tx, user.id, Some("rolled@example.com"), None)
        .await
        .expect("update user")
        .expect("live user");
    tx.rollback().await.expect("rollback");

    let reread = repo.get_user(user.id).await.expect("get").expect("live");
    assert_eq!(reread.user_email, "old@example.com");

    cleanup(&pool, &user.user_sub).await;
}

async fn update_grant(
    pool: &PgPool,
    id: Uuid,
    action: Option<GrantAction>,
    constraints: serde_json::Value,
) -> Option<PermissionsGrant> {
    let mut tx = pool.begin().await.expect("begin");
    let updated = grants::tx_update_grant(&mut tx, id, action, &constraints)
        .await
        .expect("update grant");
    tx.commit().await.expect("commit");
    updated
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn update_grant_keeps_action_when_none_and_replaces_constraints() {
    let pool = state_pool().await;
    let repo = PgPermissionsRepo::new(pool.clone());
    let user = seed_user(&repo, "tx-update-grant").await;
    let grant = seed_grant(&repo, user.id).await;

    let tightened = update_grant(&pool, grant.id, None, json!({ "require_reason": true }))
        .await
        .expect("live grant updates");
    assert_eq!(tightened.action, GrantAction::QueryRead, "action untouched");
    assert_eq!(
        tightened.constraints,
        json!({ "require_reason": true }),
        "constraints are replaced wholesale — the caller merged them"
    );
    assert_eq!(tightened.target, grant.target, "target is immutable");

    let reactioned = update_grant(&pool, grant.id, Some(GrantAction::SchemaRead), json!({}))
        .await
        .expect("live grant updates");
    assert_eq!(reactioned.action, GrantAction::SchemaRead);
    let reread = repo.get_grant(grant.id).await.expect("get").expect("live");
    assert_eq!(reread, reactioned);

    cleanup(&pool, &user.user_sub).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn update_grant_never_resurrects_a_revoked_grant() {
    let pool = state_pool().await;
    let repo = PgPermissionsRepo::new(pool.clone());
    let user = seed_user(&repo, "tx-update-revoked").await;
    let grant = seed_grant(&repo, user.id).await;

    assert!(repo.revoke_grant(grant.id).await.expect("revoke"));
    assert!(
        update_grant(&pool, grant.id, Some(GrantAction::QueryWrite), json!({}))
            .await
            .is_none(),
        "a revoked grant must not come back as query_write"
    );
    assert!(repo.get_grant(grant.id).await.expect("get").is_none());
    assert!(
        update_grant(&pool, Uuid::new_v4(), None, json!({}))
            .await
            .is_none()
    );

    cleanup(&pool, &user.user_sub).await;
}
