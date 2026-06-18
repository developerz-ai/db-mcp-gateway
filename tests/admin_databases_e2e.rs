//! Integration tests for `/admin/v1/databases` (#53).
//!
//! Boots the gateway against the dev state DB (`bin/dev up`). Each test mints
//! its own session JWT directly (skipping OIDC) — mirrors the harness used by
//! `admin_users_e2e.rs`.
//!
//! Acceptance from #53:
//!  - CRUD endpoints work for admin
//!  - DSN-shaped fields in POST/PATCH are rejected (the headline criterion)
//!  - unknown `db_type` rejected
//!  - non-admin → 403, no data row, no audit row
//!  - every write produces an audit row
//!
//! The audit-failure-rolls-back property was proven end-to-end in #52
//! (`admin_users_e2e::audit_write_failure_rolls_back_user_write`); the same
//! tx pattern is reused here, so the proof carries over without a second
//! rollback-injection test in this file.

use std::sync::Arc;
use std::time::Duration;

use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore, jwt};
use db_mcp_gateway::config::{AdminBlock, Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::{PermissionsRepo, pg::PgPermissionsRepo};
use db_mcp_gateway::transport::{self, AppState, AuthFacade, PendingFlows};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

const ADMIN_GROUP: &str = "db-mcp-gateway-admins";

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

async fn mint_session(
    sessions: &SessionStore,
    signing_key: &[u8],
    user_sub: &str,
    user_email: &str,
    groups: &[String],
) -> String {
    let session = sessions
        .create(
            user_sub,
            user_email,
            groups,
            Duration::from_secs(600),
            Some("admin-db-e2e/0.1"),
        )
        .await
        .expect("create session");
    jwt::issue(signing_key, session.id, user_sub, Duration::from_secs(600)).expect("issue JWT")
}

struct Harness {
    base_url: String,
    pool: PgPool,
    cleanup_db_ids: Vec<Uuid>,
    cleanup_admin_subs: Vec<String>,
}

impl Harness {
    fn track_db(&mut self, id: Uuid) {
        self.cleanup_db_ids.push(id);
    }

    fn track_admin(&mut self, sub: impl Into<String>) {
        self.cleanup_admin_subs.push(sub.into());
    }

    async fn cleanup(&self) {
        for id in &self.cleanup_db_ids {
            let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
                .bind(id)
                .execute(&self.pool)
                .await;
            let _ = sqlx::query("DELETE FROM permissions_databases WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await;
        }
        for sub in &self.cleanup_admin_subs {
            let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
                .bind(sub)
                .execute(&self.pool)
                .await;
        }
    }
}

async fn spawn_gateway() -> (Harness, AuthConfig, SessionStore) {
    let pool = pool().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let auth_config = AuthConfig {
        issuer: "http://idp.invalid".to_string(),
        client_id: "test".to_string(),
        client_secret: "test".to_string(),
        audience: "test".to_string(),
        redirect_url: format!("{base_url}/auth/callback"),
        ..AuthConfig::default()
    };
    let sessions = SessionStore::new(pool.clone());
    let oidc = OidcClient::new(auth_config.clone()).expect("OidcClient builds");

    let mut config_file = ConfigFile::from_yaml_str("servers: []\npermissions: []\n").unwrap();
    config_file.admin = Some(AdminBlock {
        enabled: true,
        group: ADMIN_GROUP.to_string(),
    });

    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));

    let config = Config {
        bind: addr,
        ..Config::default()
    };
    let app = transport::router(
        &config,
        AppState {
            auth: Some(AuthFacade {
                config: Arc::new(auth_config.clone()),
                sessions: sessions.clone(),
                oidc,
                flows: PendingFlows::default(),
            }),
            config: Arc::new(config_file),
            adapter_registry: AdapterRegistry::new(),
            state_db: Some(pool.clone()),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: Some(repo),
        },
    )
    .expect("router builds");
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    (
        Harness {
            base_url,
            pool,
            cleanup_db_ids: Vec::new(),
            cleanup_admin_subs: Vec::new(),
        },
        auth_config,
        sessions,
    )
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn latest_audit_for_target(
    pool: &PgPool,
    target_id: Uuid,
) -> Option<(String, Option<Value>, Option<Value>)> {
    sqlx::query(
        "SELECT action, before, after \
         FROM permissions_audit \
         WHERE target_id = $1 AND target_type = 'database' \
         ORDER BY ts DESC, id DESC LIMIT 1",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .expect("audit query")
    .map(|r| {
        (
            r.try_get::<String, _>("action").unwrap(),
            r.try_get::<Option<Value>, _>("before").unwrap(),
            r.try_get::<Option<Value>, _>("after").unwrap(),
        )
    })
}

async fn admin_jwt(
    sessions: &SessionStore,
    auth_cfg: &AuthConfig,
    h: &mut Harness,
) -> (String, String) {
    let admin_sub = format!("admin-db-e2e-{}", Uuid::new_v4().simple());
    h.track_admin(admin_sub.clone());
    let jwt = mint_session(
        sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;
    (jwt, admin_sub)
}

#[tokio::test]
async fn admin_creates_database_and_audit_row_recorded() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    let resp = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "prod",
            "db_name": format!("app-{}", Uuid::new_v4().simple()),
            "db_type": "postgres",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    h.track_db(id);
    assert_eq!(body["server"], "prod");
    assert_eq!(body["db_type"], "postgres");
    assert!(
        body.get("connection_string").is_none(),
        "response must not include any DSN field"
    );

    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "create");
    assert!(audit.1.is_none(), "create row before must be null");
    assert!(audit.2.is_some(), "create row after must carry payload");
    // Defense in depth: the audit payload must not contain anything DSN-shaped.
    let after = audit.2.unwrap();
    for forbidden in ["connection_string", "dsn", "password", "role"] {
        assert!(
            after.get(forbidden).is_none(),
            "audit row leaked {forbidden}: {after}"
        );
    }

    h.cleanup().await;
}

/// **Headline #53 acceptance.** A POST body carrying ANY DSN-shaped field —
/// `connection_string`, `dsn`, `password`, `role` — must be rejected at the
/// parse layer. `#[serde(deny_unknown_fields)]` on `CreateDatabaseRequest`
/// is what enforces this.
#[tokio::test]
async fn post_with_dsn_field_is_rejected() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    let target_name = format!("app-{}", Uuid::new_v4().simple());

    for forbidden_field in ["connection_string", "dsn", "password", "role"] {
        let body = json!({
            "server": "prod",
            "db_name": target_name,
            "db_type": "postgres",
            forbidden_field: "should-never-be-accepted",
        });
        let resp = client()
            .post(format!("{}/admin/v1/databases", h.base_url))
            .bearer_auth(&jwt)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "body containing `{forbidden_field}` must be rejected; sent {body}"
        );
        let err: Value = resp.json().await.unwrap();
        assert_eq!(err["error"]["code"], "invalid_request");
    }

    // The data row must not exist — none of the rejected POSTs should have
    // been written.
    let exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM permissions_databases WHERE db_name = $1)")
            .bind(&target_name)
            .fetch_one(&h.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert!(!exists, "rejected POSTs must not have created any row");

    h.cleanup().await;
}

#[tokio::test]
async fn patch_with_dsn_field_is_rejected() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    // Create a real row first so PATCH has a target.
    let create: Value = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "prod",
            "db_name": format!("app-{}", Uuid::new_v4().simple()),
            "db_type": "postgres",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_db(id);

    let resp = client()
        .patch(format!("{}/admin/v1/databases/{}", h.base_url, id))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "staging",
            "connection_string": "postgres://nope:nope@h/db",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // And the row's `server` must NOT have moved to staging — the PATCH must
    // have failed at parse, never reached the handler.
    let still_prod: bool = sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM permissions_databases WHERE id = $1 AND server = 'prod')",
    )
    .bind(id)
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .try_get(0)
    .unwrap();
    assert!(
        still_prod,
        "rejected PATCH must not have changed the row's server"
    );

    h.cleanup().await;
}

#[tokio::test]
async fn unknown_db_type_is_rejected() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    // `mongo` is intentionally excluded from the permissions-store db_type per
    // spec 12 §"Storage backends" — mongo lands as a query target, not as a
    // permissions backend.
    let resp = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "prod",
            "db_name": format!("app-{}", Uuid::new_v4().simple()),
            "db_type": "mongo",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: Value = resp.json().await.unwrap();
    assert_eq!(err["error"]["code"], "invalid_request");
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("db_type"),
        "error message must name the field; got {err}"
    );

    h.cleanup().await;
}

#[tokio::test]
async fn patch_updates_and_audits_before_and_after() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    let original_name = format!("app-{}", Uuid::new_v4().simple());
    let create: Value = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "prod",
            "db_name": original_name,
            "db_type": "postgres",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_db(id);

    let renamed = format!("renamed-{}", Uuid::new_v4().simple());
    let resp = client()
        .patch(format!("{}/admin/v1/databases/{}", h.base_url, id))
        .bearer_auth(&jwt)
        .json(&json!({ "db_name": renamed, "db_type": "mysql" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["db_name"], renamed);
    assert_eq!(v["db_type"], "mysql");
    assert_eq!(
        v["server"], "prod",
        "PATCH without `server` leaves it unchanged"
    );

    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "update");
    assert_eq!(audit.1.as_ref().unwrap()["db_name"], original_name);
    assert_eq!(audit.2.as_ref().unwrap()["db_name"], renamed);
    assert_eq!(audit.1.as_ref().unwrap()["db_type"], "postgres");
    assert_eq!(audit.2.as_ref().unwrap()["db_type"], "mysql");

    h.cleanup().await;
}

#[tokio::test]
async fn delete_soft_deletes_and_audits() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    let create: Value = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "prod",
            "db_name": format!("app-{}", Uuid::new_v4().simple()),
            "db_type": "postgres",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_db(id);

    let resp = client()
        .delete(format!("{}/admin/v1/databases/{}", h.base_url, id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = client()
        .get(format!("{}/admin/v1/databases/{}", h.base_url, id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "delete");
    assert!(audit.1.is_some(), "delete row must carry before");
    assert!(audit.2.is_none(), "delete row must omit after");

    h.cleanup().await;
}

#[tokio::test]
async fn list_excludes_soft_deleted() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (jwt, _) = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    let alive_name = format!("alive-{}", Uuid::new_v4().simple());
    let dead_name = format!("dead-{}", Uuid::new_v4().simple());

    let alive: Value = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({ "server": "prod", "db_name": alive_name, "db_type": "postgres" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let dead: Value = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({ "server": "prod", "db_name": dead_name, "db_type": "postgres" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let alive_id: Uuid = alive["id"].as_str().unwrap().parse().unwrap();
    let dead_id: Uuid = dead["id"].as_str().unwrap().parse().unwrap();
    h.track_db(alive_id);
    h.track_db(dead_id);

    let _ = client()
        .delete(format!("{}/admin/v1/databases/{}", h.base_url, dead_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let list: Vec<Value> = client()
        .get(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = list
        .iter()
        .map(|d| d["db_name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&alive_name.as_str()), "alive present");
    assert!(!names.contains(&dead_name.as_str()), "dead excluded");

    h.cleanup().await;
}

#[tokio::test]
async fn non_admin_gets_403_and_no_writes() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let nonadmin_sub = format!("nonadmin-db-e2e-{}", Uuid::new_v4().simple());
    h.track_admin(nonadmin_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &nonadmin_sub,
        "rando@example.com",
        &["engineers".to_string()],
    )
    .await;

    let body_name = format!("app-{}", Uuid::new_v4().simple());
    let resp = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({ "server": "prod", "db_name": body_name, "db_type": "postgres" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");

    // No data row.
    let exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM permissions_databases WHERE db_name = $1)")
            .bind(&body_name)
            .fetch_one(&h.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert!(!exists, "non-admin must not insert a row");

    // No audit row from this caller.
    let n: i64 = sqlx::query(
        "SELECT COUNT(*) FROM permissions_audit WHERE actor_email = 'rando@example.com' \
         AND target_type = 'database'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .try_get(0)
    .unwrap();
    assert_eq!(n, 0, "non-admin 403 must not write any audit row");

    h.cleanup().await;
}

#[tokio::test]
async fn anonymous_gets_401() {
    let (h, _, _) = spawn_gateway().await;
    let resp = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .json(&json!({ "server": "x", "db_name": "y", "db_type": "postgres" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
