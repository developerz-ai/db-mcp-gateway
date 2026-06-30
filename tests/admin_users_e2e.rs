//! Integration tests for `/admin/v1/users` (#52).
//!
//! Boots the gateway against the dev state DB (`bin/dev up`). Each test mints
//! its own session JWT directly (skipping the OIDC flow that `auth_e2e.rs`
//! exercises) so we can vary the caller's groups per test without spinning up
//! a mock IdP each time.
//!
//! Acceptance from #52:
//!  - admin allowed across CRUD
//!  - non-admin → 403, no data write, no audit row
//!  - every write produces an audit row
//!
//! Also covers the rollback path deferred from #51: an audit-write failure
//! must roll back the data write end-to-end.
//!
//! Tests use unique `user_sub` values and clean up after themselves so they
//! coexist with each other and with dev rows.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Request;
use axum::middleware as axum_mw;
use axum::middleware::Next;
use db_mcp_gateway::auth::{AuthConfig, OidcClient, SessionStore, jwt};
use db_mcp_gateway::config::{AdminBlock, Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::{PermissionsRepo, pg::PgPermissionsRepo};
use db_mcp_gateway::transport::admin;
use db_mcp_gateway::transport::admin::middleware::AdminActor;
use db_mcp_gateway::transport::admin::users::UsersState;
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

/// Insert a session row, mint a JWT for it, and return both.
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
            Some("admin-e2e/0.1"),
            None,
        )
        .await
        .expect("create session");
    jwt::issue(signing_key, session.id, user_sub, Duration::from_secs(600)).expect("issue JWT")
}

struct Harness {
    base_url: String,
    pool: PgPool,
    cleanup_subs: Vec<String>,
}

impl Harness {
    fn track(&mut self, sub: impl Into<String>) {
        self.cleanup_subs.push(sub.into());
    }

    async fn cleanup(&self) {
        for sub in &self.cleanup_subs {
            // Both the permissions row AND any audit rows referencing it.
            let id: Option<Uuid> =
                sqlx::query("SELECT id FROM permissions_users WHERE user_sub = $1 LIMIT 1")
                    .bind(sub)
                    .fetch_optional(&self.pool)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|r| r.try_get::<Uuid, _>("id").ok());
            if let Some(uid) = id {
                let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
                    .bind(uid)
                    .execute(&self.pool)
                    .await;
            }
            let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
                .bind(sub)
                .execute(&self.pool)
                .await;
            // Also clean up the admin actor's row (created by middleware).
            let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub LIKE 'admin-e2e-%'")
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
        // The OIDC fields don't matter — tests bypass the login flow.
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
        session_max_age_secs: None,
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
                codes: db_mcp_gateway::transport::AuthCodes::default(),
                refresh: db_mcp_gateway::transport::RefreshTokens::default(),
            }),
            config: Arc::new(config_file),
            adapter_registry: AdapterRegistry::new(),
            state_db: Some(pool.clone()),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: Some(repo),
            mcp_path: std::sync::Arc::from("/mcp"),
            client_registry: db_mcp_gateway::transport::ClientRegistry::default(),
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
            cleanup_subs: Vec::new(),
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
) -> Option<(String, Option<Value>, Option<Value>, String, String)> {
    let row = sqlx::query(
        "SELECT action, before, after, request_id, actor_email \
         FROM permissions_audit \
         WHERE target_id = $1 \
         ORDER BY ts DESC, id DESC LIMIT 1",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .expect("audit query");
    row.map(|r| {
        (
            r.try_get::<String, _>("action").unwrap(),
            r.try_get::<Option<Value>, _>("before").unwrap(),
            r.try_get::<Option<Value>, _>("after").unwrap(),
            r.try_get::<String, _>("request_id").unwrap(),
            r.try_get::<String, _>("actor_email").unwrap(),
        )
    })
}

#[tokio::test]
async fn admin_can_create_user_then_audit_row_recorded() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    let resp = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "target@example.com",
            "groups": ["engineers"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    let target_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(body["user_sub"], target_sub);
    assert_eq!(body["user_email"], "target@example.com");

    let audit = latest_audit_for_target(&h.pool, target_id)
        .await
        .expect("audit");
    assert_eq!(audit.0, "create");
    assert!(audit.1.is_none(), "create row before must be null");
    assert!(audit.2.is_some(), "create row after must carry payload");
    assert_eq!(audit.4, "admin@example.com");
    assert!(!audit.3.is_empty(), "request_id non-empty");

    h.cleanup().await;
}

#[tokio::test]
async fn admin_repeat_create_logs_as_update() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    let body = json!({
        "user_sub": target_sub,
        "user_email": "v1@example.com",
        "groups": ["engineers"],
    });
    let _ = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let body2 = json!({
        "user_sub": target_sub,
        "user_email": "v2@example.com",
        "groups": ["engineers", "oncall"],
    });
    let resp = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&body2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    let target_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    let audit = latest_audit_for_target(&h.pool, target_id)
        .await
        .expect("audit");
    assert_eq!(audit.0, "update");
    assert!(audit.1.is_some(), "update row must carry before");
    assert!(audit.2.is_some(), "update row must carry after");

    h.cleanup().await;
}

#[tokio::test]
async fn non_admin_gets_403_and_no_writes() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let nonadmin_sub = format!("nonadmin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());
    h.track(nonadmin_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &nonadmin_sub,
        "rando@example.com",
        &["engineers".to_string()],
    )
    .await;

    let resp = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "target@example.com",
            "groups": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "forbidden");

    // No data row.
    let exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM permissions_users WHERE user_sub = $1)")
            .bind(&target_sub)
            .fetch_one(&h.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert!(!exists, "non-admin call must not insert a user row");

    // No audit row anywhere referencing target_sub (target hasn't been
    // upserted, so we can't look up by id — assert by recent ts + actor_email).
    let recent_count: i64 = sqlx::query(
        "SELECT COUNT(*) FROM permissions_audit WHERE actor_email = 'rando@example.com'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .try_get(0)
    .unwrap();
    assert_eq!(
        recent_count, 0,
        "non-admin 403 must not write any audit row"
    );

    h.cleanup().await;
}

#[tokio::test]
async fn anonymous_gets_401() {
    let (h, _auth_cfg, _sessions) = spawn_gateway().await;
    let resp = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .json(&json!({
            "user_sub": "anon",
            "user_email": "anon@example.com",
            "groups": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_patches_user_audit_carries_before_and_after() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;
    let create: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "old@example.com",
            "groups": ["engineers"],
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let target_id: Uuid = create["id"].as_str().unwrap().parse().unwrap();

    let resp = client()
        .patch(format!("{}/admin/v1/users/{}", h.base_url, target_id))
        .bearer_auth(&jwt)
        .json(&json!({ "user_email": "new@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["user_email"], "new@example.com");
    assert_eq!(
        v["groups"],
        json!(["engineers"]),
        "PATCH without groups leaves groups unchanged"
    );

    let audit = latest_audit_for_target(&h.pool, target_id)
        .await
        .expect("audit");
    assert_eq!(audit.0, "update");
    assert_eq!(audit.1.as_ref().unwrap()["user_email"], "old@example.com");
    assert_eq!(audit.2.as_ref().unwrap()["user_email"], "new@example.com");

    h.cleanup().await;
}

#[tokio::test]
async fn delete_soft_deletes_and_audits() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;
    let create: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "doomed@example.com",
            "groups": [],
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let target_id: Uuid = create["id"].as_str().unwrap().parse().unwrap();

    let resp = client()
        .delete(format!("{}/admin/v1/users/{}", h.base_url, target_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = client()
        .get(format!("{}/admin/v1/users/{}", h.base_url, target_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let audit = latest_audit_for_target(&h.pool, target_id)
        .await
        .expect("audit");
    assert_eq!(audit.0, "delete");
    assert!(audit.1.is_some(), "delete row must carry before");
    assert!(audit.2.is_none(), "delete row must omit after");

    h.cleanup().await;
}

#[tokio::test]
async fn list_excludes_soft_deleted() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let alive_sub = format!("alive-e2e-{}", Uuid::new_v4().simple());
    let dead_sub = format!("dead-e2e-{}", Uuid::new_v4().simple());
    h.track(alive_sub.clone());
    h.track(dead_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    let alive: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({ "user_sub": alive_sub, "user_email": "a@example.com", "groups": [] }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let dead: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({ "user_sub": dead_sub, "user_email": "d@example.com", "groups": [] }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let dead_id: Uuid = dead["id"].as_str().unwrap().parse().unwrap();
    let _ = client()
        .delete(format!("{}/admin/v1/users/{}", h.base_url, dead_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    let list: Vec<Value> = client()
        .get(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let subs: Vec<&str> = list
        .iter()
        .map(|u| u["user_sub"].as_str().unwrap())
        .collect();
    assert!(
        subs.iter()
            .any(|s| *s == alive["user_sub"].as_str().unwrap()),
        "alive present"
    );
    assert!(
        !subs
            .iter()
            .any(|s| *s == dead["user_sub"].as_str().unwrap()),
        "dead excluded"
    );

    h.cleanup().await;
}

/// ADM1: a read-only GET must NOT create a `permissions_users` row for the
/// acting admin. Previously the middleware unconditionally upserted the actor
/// row; after ADM1 that upsert moved inside mutation transactions (POST /
/// PATCH / DELETE). A GET handler never opens one, so a brand-new admin sub
/// that only ever GETs should remain absent from `permissions_users`.
#[tokio::test]
async fn get_does_not_write_user_row() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    // Use a unique sub that has NEVER been written via a mutation.
    let admin_sub = format!("admin-get-only-{}", uuid::Uuid::new_v4().simple());
    // Track for cleanup (in case we regress and accidentally insert the row).
    h.track(admin_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin-get@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    // List call — read-only GET. Must succeed for an admin.
    let resp = client()
        .get(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET list must succeed for admin"
    );

    // The GET must NOT have written a `permissions_users` row for this admin.
    let exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM permissions_users WHERE user_sub = $1)")
            .bind(&admin_sub)
            .fetch_one(&h.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert!(
        !exists,
        "GET must not create a permissions_users row for the admin actor"
    );

    h.cleanup().await;
}

/// Audit write must fail the request AND roll back the data write. The
/// production middleware always provides a non-empty `request_id`, so to
/// exercise the rollback path we bypass that middleware and inject an
/// AdminActor with an empty request_id — which trips the
/// `permissions_audit_request_id_not_empty` CHECK from migration 0005.
///
/// This is the integration test deferred from #51 (PR #65).
#[tokio::test]
async fn audit_write_failure_rolls_back_user_write() {
    let pool = pool().await;
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));

    let admin_email = format!("admin-rollback-{}@example.com", Uuid::new_v4().simple());
    let admin_sub = format!("admin-rollback-{}", Uuid::new_v4().simple());

    let target_sub = format!("target-rollback-{}", Uuid::new_v4().simple());

    let users_state = UsersState {
        repo: repo.clone(),
        state_db: pool.clone(),
    };
    // The handler calls tx_upsert_actor inside the transaction, so the actor
    // row is not pre-seeded here. The empty request_id trips the CHECK on
    // permissions_audit.request_id (migration 0005), causing the transaction
    // — including the upserted actor row and the target user write — to roll back.
    let actor = AdminActor {
        sub: admin_sub.clone(),
        email: admin_email.clone(),
        groups: vec![ADMIN_GROUP.to_string()],
        // Empty — trips the CHECK on permissions_audit.request_id, forcing
        // the transaction to roll back.
        request_id: String::new(),
    };

    // The production `/admin/v1/users` route stacks `require_admin_group` over
    // the handler; that middleware always produces a non-empty request_id, so
    // it can't reach this rollback path. The test wires a bespoke router that
    // injects the bad actor directly into request extensions and routes to
    // the same handler the production router uses.
    let app: Router = Router::new()
        .route("/users", axum::routing::post(admin::users::create))
        .layer(axum_mw::from_fn({
            let actor = actor.clone();
            move |mut req: Request, next: Next| {
                let actor = actor.clone();
                async move {
                    req.extensions_mut().insert(actor);
                    next.run(req).await
                }
            }
        }))
        .with_state(users_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let resp = client()
        .post(format!("{base_url}/users"))
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "target@example.com",
            "groups": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Data row must NOT exist — the transaction rolled back when the audit
    // CHECK constraint blew up the audit INSERT.
    let exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM permissions_users WHERE user_sub = $1)")
            .bind(&target_sub)
            .fetch_one(&pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert!(
        !exists,
        "user row must roll back when the audit write fails"
    );

    // Cleanup admin seed.
    let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(&admin_sub)
        .execute(&pool)
        .await;
}

/// Malformed JSON body must surface as the stable admin-error envelope
/// (`invalid_request` + `request_id`), not Axum's default 400/422. Belt-and-
/// suspenders for the contract the docs sell: every admin failure carries a
/// stable code AND a request_id, so an operator can paste the id into Loki
/// and grep all three places (response, log, audit). Pairs with the fallible
/// extractor change in `src/transport/admin/users.rs`.
#[tokio::test]
async fn malformed_json_returns_invalid_request_envelope() {
    let (h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    let resp = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["request_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "every admin error envelope must carry request_id"
    );

    // Defensive: middleware upserts the admin actor row before the handler
    // sees the body, so clean it up.
    let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(&admin_sub)
        .execute(&h.pool)
        .await;
}

/// Invalid UUID in `:id` must also produce the stable admin-error envelope.
#[tokio::test]
async fn invalid_path_id_returns_invalid_request_envelope() {
    let (h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    let resp = client()
        .get(format!("{}/admin/v1/users/not-a-uuid", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["request_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "every admin error envelope must carry request_id"
    );

    let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(&admin_sub)
        .execute(&h.pool)
        .await;
}

/// `admin.enabled = false` keeps the entire `/admin/*` surface unmounted —
/// the request hits axum's default 404, not the admin error JSON. Belt-and-
/// suspenders for YAML-only installs that explicitly opt out (spec 12
/// §"Admin API"). Pairs with the enabled-path coverage above.
#[tokio::test]
async fn admin_disabled_returns_404_on_admin_routes() {
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

    // Same YAML as the enabled tests but with admin block explicitly disabled.
    let mut config_file = ConfigFile::from_yaml_str("servers: []\npermissions: []\n").unwrap();
    config_file.admin = Some(AdminBlock {
        enabled: false,
        group: ADMIN_GROUP.to_string(),
        session_max_age_secs: None,
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
                codes: db_mcp_gateway::transport::AuthCodes::default(),
                refresh: db_mcp_gateway::transport::RefreshTokens::default(),
            }),
            config: Arc::new(config_file),
            adapter_registry: AdapterRegistry::new(),
            state_db: Some(pool.clone()),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: None,
            permissions_repo: Some(repo),
            mcp_path: std::sync::Arc::from("/mcp"),
            client_registry: db_mcp_gateway::transport::ClientRegistry::default(),
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

    // Mint an admin-group bearer so we can prove the 404 is from "unmounted
    // route", not "auth failed" — otherwise this test would also pass on a
    // broken build that left the surface mounted but rejected the caller.
    let admin_sub = format!("admin-disabled-{}", Uuid::new_v4().simple());
    let jwt = mint_session(
        &sessions,
        &auth_config.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    for path in [
        "/admin/v1/users",
        "/admin/v1/users/00000000-0000-0000-0000-000000000000",
    ] {
        let resp = client()
            .get(format!("{base_url}{path}"))
            .bearer_auth(&jwt)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must be unmounted when admin.enabled=false"
        );
    }

    // Cleanup any row the admin's bearer would have created (none, since
    // the admin upsert lives behind the middleware — but defensive cleanup
    // keeps the test independent of that contract).
    let _ = sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(&admin_sub)
        .execute(&pool)
        .await;
}
