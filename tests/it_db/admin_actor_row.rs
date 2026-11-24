//! A5: an admin mutation records its actor without rewriting the actor's
//! `permissions_users` row. The row is inserted if absent and otherwise left
//! exactly as the audited writes last left it — no unaudited email/groups
//! refresh, no `updated_at` bump that turns another admin's precondition
//! into a spurious 409.

use std::sync::Arc;
use std::time::Duration;

use crate::common::cleanup::{delete_permissions_audit, delete_permissions_user};
use crate::common::env::state_pool;
use crate::common::gateway::GatewayBuilder;
use db_mcp_gateway::auth::{SessionStore, jwt};
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use reqwest::StatusCode;
use secrecy::SecretSlice;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

const YAML: &str = "permissions: []\n";
const ADMIN_GROUP: &str = "db-mcp-gateway-admins";

async fn bearer(
    sessions: &SessionStore,
    key: &SecretSlice<u8>,
    sub: &str,
    email: &str,
    groups: &[&str],
) -> String {
    let groups: Vec<String> = groups.iter().map(|g| (*g).to_string()).collect();
    let session = sessions
        .create(sub, email, &groups, Duration::from_secs(600), None)
        .await
        .expect("create session");
    jwt::issue(key, session.id, sub, Duration::from_secs(600)).expect("issue JWT")
}

async fn create_user(base: &str, bearer: &str, sub: &str) -> Value {
    let resp = reqwest::Client::new()
        .post(format!("{base}/admin/v1/users"))
        .bearer_auth(bearer)
        .json(&json!({ "user_sub": sub, "user_email": "t@example.com", "groups": [] }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::CREATED);
    resp.json().await.expect("json")
}

async fn actor_row(
    pool: &PgPool,
    sub: &str,
) -> (Uuid, String, Value, chrono::DateTime<chrono::Utc>) {
    let row = sqlx::query(
        "SELECT id, user_email, groups, updated_at FROM permissions_users \
         WHERE user_sub = $1 AND deleted_at IS NULL",
    )
    .bind(sub)
    .fetch_one(pool)
    .await
    .expect("actor row exists");
    (
        row.get("id"),
        row.get("user_email"),
        row.get("groups"),
        row.get("updated_at"),
    )
}

async fn cleanup(pool: &PgPool, subs: &[&str]) {
    for sub in subs {
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM permissions_users WHERE user_sub = $1 LIMIT 1")
                .bind(sub)
                .fetch_optional(pool)
                .await
                .expect("lookup");
        if let Some(id) = id {
            delete_permissions_audit(pool, id).await;
        }
        delete_permissions_user(pool, sub).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn admin_writes_never_rewrite_the_existing_actor_row() {
    let pool = state_pool().await;
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let gw = GatewayBuilder::new(YAML)
        .admin(ADMIN_GROUP, true)
        .repo(repo)
        .spawn(pool.clone())
        .await;
    let key = &gw.auth_config.session_signing_key;
    let unique = Uuid::new_v4().simple().to_string();
    let (admin, other, t1, t2) = (
        format!("actor-a5-{unique}"),
        format!("actor-a5-other-{unique}"),
        format!("actor-a5-t1-{unique}"),
        format!("actor-a5-t2-{unique}"),
    );

    // First write inserts the absent actor row from the session snapshot.
    let first = bearer(&gw.sessions, key, &admin, "a@example.com", &[ADMIN_GROUP]).await;
    create_user(&gw.url, &first, &t1).await;
    let before = actor_row(&pool, &admin).await;
    assert_eq!(before.1, "a@example.com");

    // The IdP now reports a different email and groups for the same subject.
    let second = bearer(
        &gw.sessions,
        key,
        &admin,
        "renamed@example.com",
        &[ADMIN_GROUP, "extra"],
    )
    .await;
    create_user(&gw.url, &second, &t2).await;
    let after = actor_row(&pool, &admin).await;
    assert_eq!(
        after, before,
        "an admin write rewrote its actor row unaudited"
    );

    // Another admin's precondition on the actor row still holds.
    let other_bearer = bearer(&gw.sessions, key, &other, "o@example.com", &[ADMIN_GROUP]).await;
    let resp = reqwest::Client::new()
        .patch(format!("{}/admin/v1/users/{}", gw.url, before.0))
        .bearer_auth(&other_bearer)
        .json(&json!({ "groups": ["audited"], "expected_updated_at": before.3 }))
        .send()
        .await
        .expect("send");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "spurious 409 on the actor row"
    );

    // The audited chain on the actor row: its one update's `before` is the
    // row as inserted, not a silently refreshed copy.
    let audit_before: Value = sqlx::query(
        "SELECT before FROM permissions_audit WHERE target_id = $1 AND action = 'update'",
    )
    .bind(before.0)
    .fetch_one(&pool)
    .await
    .expect("one audited update of the actor row")
    .get("before");
    assert_eq!(audit_before["user_email"], "a@example.com");

    cleanup(&pool, &[&t1, &t2, &other, &admin]).await;
}
