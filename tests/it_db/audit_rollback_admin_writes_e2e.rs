//! MUST #5: an admin write whose `permissions_audit` row fails to commit is
//! not applied. `admin_users_e2e` proves it for users; this file for the
//! databases and grants routes. The production middleware always sets a
//! request id, so — as there — a bespoke router injects an `AdminActor` with
//! an empty one, which trips the `permissions_audit.request_id` CHECK
//! (migration 0005) inside the handler's transaction.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use axum::Router;
use axum::extract::Request;
use axum::middleware::{self as axum_mw, Next};
use axum::routing::post;
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::ConfigFile;
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::transport::admin::databases::{self, DatabasesState};
use db_mcp_gateway::transport::admin::grants::{self, GrantsState};
use db_mcp_gateway::transport::admin::middleware::AdminActor;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::env::state_pool;

const YAML: &str = r#"
servers:
  - name: rollback
    kind: postgres
    host: localhost
    port: 5434
    tls: insecure
    databases:
      - name: app
        role: app
        password: app-dev-only
permissions: []
"#;

/// An actor whose empty request id makes the audit INSERT fail.
fn unauditable_actor() -> AdminActor {
    AdminActor {
        sub: format!("admin-rollback-{}", Uuid::new_v4().simple()),
        email: "admin-rollback@example.com".to_string(),
        groups: vec!["gateway-admins".to_string()],
        request_id: String::new(),
    }
}

/// Serve `router` behind a layer that injects [`unauditable_actor`].
async fn serve(router: Router) -> String {
    let actor = unauditable_actor();
    let app = router.layer(axum_mw::from_fn(move |mut req: Request, next: Next| {
        let actor = actor.clone();
        async move {
            req.extensions_mut().insert(actor);
            next.run(req).await
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

async fn post_json(url: String, body: Value) -> StatusCode {
    reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
}

async fn count(pool: &PgPool, sql: &'static str, key: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn repo_and_cache(pool: &PgPool) -> (Arc<dyn PermissionsRepo>, PermissionsCache) {
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let cache = PermissionsCache::new(repo.clone(), Duration::from_secs(60));
    (repo, cache)
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn audit_write_failure_rolls_back_a_database_create() {
    let pool = state_pool().await;
    let (repo, cache) = repo_and_cache(&pool);
    // A name no other test registers, so the count below is this test's.
    let db_name = format!("rollback_{}", Uuid::new_v4().simple());
    let yaml = YAML.replace("name: app\n", &format!("name: {db_name}\n"));
    let config = ConfigFile::from_yaml_str(&yaml).expect("rollback yaml parses");
    let state = DatabasesState {
        repo,
        state_db: pool.clone(),
        cache,
        known_servers: Arc::from(vec!["rollback".to_string()]),
        config: Arc::new(ArcSwap::from_pointee(config)),
    };
    let url = serve(
        Router::new()
            .route("/databases", post(databases::create))
            .with_state(state),
    )
    .await;

    let body = json!({"server": "rollback", "db_name": db_name, "db_type": "postgres"});
    let status = post_json(format!("{url}/databases"), body).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let rows = count(
        &pool,
        "SELECT count(*) FROM permissions_databases WHERE db_name = $1",
        &db_name,
    )
    .await;
    assert_eq!(
        rows, 0,
        "the database row must roll back with its audit row"
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn audit_write_failure_rolls_back_a_grant_create() {
    let pool = state_pool().await;
    let (repo, cache) = repo_and_cache(&pool);
    let user_sub = format!("grant-rollback-{}", Uuid::new_v4().simple());
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO permissions_users (user_sub, user_email) VALUES ($1, 'g@example.com') \
         RETURNING id",
    )
    .bind(&user_sub)
    .fetch_one(&pool)
    .await
    .unwrap();
    let state = GrantsState {
        repo,
        state_db: pool.clone(),
        cache,
        known_servers: Arc::from(vec!["rollback".to_string()]),
    };
    let url = serve(
        Router::new()
            .route("/grants", post(grants::create))
            .with_state(state),
    )
    .await;

    let body = json!({
        "user_id": user_id,
        "server": "rollback",
        "db_name_wildcard": true,
        "action": "query_read",
    });
    let status = post_json(format!("{url}/grants"), body).await;

    let grants: i64 =
        sqlx::query_scalar("SELECT count(*) FROM permissions_grants WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("DELETE FROM permissions_users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(grants, 0, "the grant row must roll back with its audit row");
}
