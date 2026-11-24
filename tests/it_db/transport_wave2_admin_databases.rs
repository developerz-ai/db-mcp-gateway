//! `/admin/v1/databases` only registers databases the gateway config declares
//! — server and database (A4) — the same rule a wildcard grant already obeys,
//! so no row can sit dormant until a later reload arms it. A refused
//! create or rename writes neither a row nor a `permissions_audit` entry
//! (spec 12: a rejected request leaves the store and the audit table
//! unchanged). Requires the dev state DB (`bin/dev up`).

use std::sync::Arc;
use std::time::Duration;

use crate::common::cleanup::{
    delete_permissions_audit, delete_permissions_database, delete_permissions_user,
};
use crate::common::env::state_pool;
use crate::common::gateway::GatewayBuilder;
use db_mcp_gateway::auth::jwt;
use db_mcp_gateway::state::permissions::{PermissionsRepo, pg::PgPermissionsRepo};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

const ADMIN_GROUP: &str = "db-mcp-gateway-admins";

const CONFIG_YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: wave2 admin
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
permissions: []
"#;

struct Harness {
    base_url: String,
    pool: PgPool,
    jwt: String,
    admin_sub: String,
    /// A database `prod` declares for this harness alone.
    declared: String,
}

async fn spawn() -> Harness {
    let pool = state_pool().await;
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let declared = format!("wave2-{}", Uuid::new_v4().simple());
    let app = "      - { name: app, role: ro, password: hunter2 }\n";
    let yaml = CONFIG_YAML.replace(
        app,
        &format!("{app}      - {{ name: {declared}, role: ro, password: hunter2 }}\n"),
    );
    let gw = GatewayBuilder::new(&yaml)
        .admin(ADMIN_GROUP, true)
        .repo(repo)
        .spawn(pool)
        .await;
    let admin_sub = format!("admin-wave2-{}", Uuid::new_v4().simple());
    let session = gw
        .sessions
        .create(
            &admin_sub,
            "admin@example.com",
            &[ADMIN_GROUP.to_string()],
            Duration::from_secs(600),
            None,
        )
        .await
        .unwrap();
    let jwt = jwt::issue(
        &gw.auth_config.session_signing_key,
        session.id,
        &admin_sub,
        Duration::from_secs(600),
    )
    .unwrap();
    Harness {
        base_url: gw.url,
        pool: gw.state_db,
        jwt,
        admin_sub,
        declared,
    }
}

impl Harness {
    async fn send(&self, method: reqwest::Method, path: &str, body: Value) -> (StatusCode, Value) {
        let response = reqwest::Client::new()
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(&self.jwt)
            .json(&body)
            .send()
            .await
            .unwrap();
        (response.status(), response.json().await.unwrap())
    }

    async fn rows_named(&self, db_name: &str) -> (i64, i64) {
        let count = |sql: &'static str| async move {
            sqlx::query(sql)
                .bind(db_name)
                .fetch_one(&self.pool)
                .await
                .unwrap()
                .try_get::<i64, _>(0)
                .unwrap()
        };
        (
            count("SELECT COUNT(*) FROM permissions_databases WHERE db_name = $1").await,
            count(
                "SELECT COUNT(*) FROM permissions_audit WHERE target_type = 'database' \
                 AND (after->>'db_name' = $1 OR before->>'db_name' = $1)",
            )
            .await,
        )
    }

    async fn cleanup(&self, ids: &[Uuid]) {
        for id in ids {
            delete_permissions_audit(&self.pool, *id).await;
            delete_permissions_database(&self.pool, *id).await;
        }
        delete_permissions_user(&self.pool, &self.admin_sub).await;
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn create_on_an_undeclared_server_is_refused_without_a_trace() {
    let h = spawn().await;
    let db_name = format!("wave2-{}", Uuid::new_v4().simple());
    let (status, err) = h
        .send(
            reqwest::Method::POST,
            "/admin/v1/databases",
            json!({ "server": "nope", "db_name": db_name, "db_type": "postgres" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["error"]["code"], "invalid_request");
    assert!(
        err["error"]["message"].as_str().unwrap().contains("server"),
        "{err}"
    );
    assert_eq!(h.rows_named(&db_name).await, (0, 0), "no row, no audit");
    h.cleanup(&[]).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn rename_onto_an_undeclared_server_is_refused_and_row_unchanged() {
    let h = spawn().await;
    let db_name = h.declared.clone();
    let (status, created) = h
        .send(
            reqwest::Method::POST,
            "/admin/v1/databases",
            json!({ "server": "prod", "db_name": db_name, "db_type": "postgres" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let (status, err) = h
        .send(
            reqwest::Method::PATCH,
            &format!("/admin/v1/databases/{id}"),
            json!({ "server": "nope" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["error"]["code"], "invalid_request");
    // Only the create's audit row; the refused PATCH left none.
    assert_eq!(h.rows_named(&db_name).await, (1, 1));
    let server: String = sqlx::query("SELECT server FROM permissions_databases WHERE id = $1")
        .bind(id)
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(server, "prod");
    h.cleanup(&[id]).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn create_of_an_undeclared_database_is_refused_without_a_trace() {
    let h = spawn().await;
    let db_name = format!("wave2-undeclared-{}", Uuid::new_v4().simple());
    let (status, err) = h
        .send(
            reqwest::Method::POST,
            "/admin/v1/databases",
            json!({ "server": "prod", "db_name": db_name, "db_type": "postgres" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["error"]["code"], "invalid_request");
    let message = err["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("db_name") && message.contains("prod"),
        "{err}"
    );
    assert_eq!(h.rows_named(&db_name).await, (0, 0), "no row, no audit");
    h.cleanup(&[]).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn rename_onto_an_undeclared_database_is_refused_and_row_unchanged() {
    let h = spawn().await;
    let db_name = h.declared.clone();
    let (status, created) = h
        .send(
            reqwest::Method::POST,
            "/admin/v1/databases",
            json!({ "server": "prod", "db_name": db_name, "db_type": "postgres" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let undeclared = format!("wave2-undeclared-{}", Uuid::new_v4().simple());
    let (status, err) = h
        .send(
            reqwest::Method::PATCH,
            &format!("/admin/v1/databases/{id}"),
            json!({ "db_name": undeclared }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{err}");
    assert_eq!(err["error"]["code"], "invalid_request");
    // Only the create's audit row; the refused PATCH left none.
    assert_eq!(h.rows_named(&db_name).await, (1, 1));
    assert_eq!(h.rows_named(&undeclared).await, (0, 0));
    h.cleanup(&[id]).await;
}

/// A13: admin bodies carry subjects, emails and grant sets — success and
/// refusal alike are `Cache-Control: no-store`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn admin_responses_are_never_cached() {
    let h = spawn().await;
    let client = reqwest::Client::new();
    let ok = client
        .get(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&h.jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(ok.headers()["cache-control"], "no-store");
    let refused = client
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&h.jwt)
        .json(&json!({ "server": "nope", "db_name": "x", "db_type": "postgres" }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(refused.headers()["cache-control"], "no-store");
    h.cleanup(&[]).await;
}
