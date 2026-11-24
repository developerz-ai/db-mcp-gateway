//! `permissions_grants.expires_at` (pg `0023`, mysql `0007`): the column is
//! there and nullable on both stores after boot migrations, existing rows
//! stay non-expiring, and both repos carry it to the resolver.

use chrono::{Duration, SubsecRound, Utc};
use db_mcp_gateway::state::permissions::mysql::MysqlPermissionsRepo;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::state::permissions::{
    GrantAction, GrantTarget, PermissionsRepo, PermissionsSeed,
};
use serde_json::json;
use uuid::Uuid;

use crate::common::cleanup::delete_permissions_user;
use crate::common::env::{mysql_pool, state_pool};

fn sub(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

async fn seed_and_read<R: PermissionsSeed>(repo: &R, user_sub: &str) -> Uuid {
    let user = repo
        .upsert_user(user_sub, "e@example.com", &[])
        .await
        .expect("user");
    let grant = repo
        .create_grant(
            user.id,
            GrantTarget::Wildcard {
                server: "prod".into(),
            },
            GrantAction::QueryRead,
            json!({}),
        )
        .await
        .expect("grant");
    assert_eq!(
        grant.expires_at, None,
        "a grant without expiry never expires"
    );
    let live = repo.live_grants_for_sub(user_sub).await.expect("live");
    assert_eq!(live[0].expires_at, None);
    grant.id
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn pg_expires_at_is_nullable_and_reaches_the_resolver() {
    let pool = state_pool().await;
    let nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
         WHERE table_name = 'permissions_grants' AND column_name = 'expires_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("0023 applied");
    assert_eq!(nullable, "YES");

    let repo = PgPermissionsRepo::new(pool.clone());
    let user_sub = sub("exp-pg");
    let id = seed_and_read(&repo, &user_sub).await;
    let at = (Utc::now() + Duration::hours(1)).trunc_subsecs(6);
    sqlx::query("UPDATE permissions_grants SET expires_at = $1 WHERE id = $2")
        .bind(at)
        .bind(id)
        .execute(&pool)
        .await
        .expect("set expiry");
    let live = repo.live_grants_for_sub(&user_sub).await.expect("live");
    assert_eq!(live[0].expires_at, Some(at));
    assert_eq!(
        repo.get_grant(id)
            .await
            .expect("get")
            .expect("row")
            .expires_at,
        Some(at)
    );

    sqlx::query("DELETE FROM permissions_grants WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("cleanup grant");
    delete_permissions_user(&pool, &user_sub).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn mysql_expires_at_is_nullable_and_reaches_the_resolver() {
    let pool = mysql_pool().await;
    let nullable: String = sqlx::query_scalar(
        "SELECT IS_NULLABLE FROM information_schema.columns \
         WHERE table_schema = DATABASE() AND table_name = 'permissions_grants' \
           AND column_name = 'expires_at'",
    )
    .fetch_one(&pool)
    .await
    .expect("0007 applied");
    assert_eq!(nullable, "YES");

    let repo = MysqlPermissionsRepo::new(pool.clone());
    let user_sub = sub("exp-my");
    let id = seed_and_read(&repo, &user_sub).await;
    let at = (Utc::now() + Duration::hours(1)).trunc_subsecs(6);
    sqlx::query("UPDATE permissions_grants SET expires_at = ? WHERE id = ?")
        .bind(at)
        .bind(id.to_string())
        .execute(&pool)
        .await
        .expect("set expiry");
    let live = repo.live_grants_for_sub(&user_sub).await.expect("live");
    assert_eq!(live[0].expires_at, Some(at));

    // Past MySQL's TIMESTAMP range (2038-01-19): the column is DATETIME(6),
    // read back as UTC, as Postgres keeps any date.
    let far = chrono::DateTime::parse_from_rfc3339("2040-06-01T12:00:00.123456Z")
        .expect("timestamp")
        .with_timezone(&Utc);
    sqlx::query("UPDATE permissions_grants SET expires_at = ? WHERE id = ?")
        .bind(far)
        .bind(id.to_string())
        .execute(&pool)
        .await
        .expect("an expiry after 2038 is stored");
    let live = repo.live_grants_for_sub(&user_sub).await.expect("live");
    assert_eq!(live[0].expires_at, Some(far));

    sqlx::query("DELETE FROM permissions_grants WHERE id = ?")
        .bind(id.to_string())
        .execute(&pool)
        .await
        .expect("cleanup grant");
    sqlx::query("DELETE FROM permissions_users WHERE user_sub = ?")
        .bind(&user_sub)
        .execute(&pool)
        .await
        .expect("cleanup user");
}
