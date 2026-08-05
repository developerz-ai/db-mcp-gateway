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
use db_mcp_gateway::auth::{AuthConfig, Identity, OidcClient, SessionId, SessionStore, jwt};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::{AdminBlock, Config, ConfigFile};
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::{
    DbType, GrantAction, GrantTarget, PermissionsRepo, pg::PgPermissionsRepo,
};
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

/// Single gateway builder shared by both entry points. `cache = Some(_)` wires
/// the resolver cache into `AppState`; `None` mirrors a YAML-only install and
/// keeps the cache-free tests honest. Kept private so every AppState field
/// addition lands in exactly one place.
async fn spawn_gateway_inner(
    cache: Option<PermissionsCache>,
) -> (Harness, AuthConfig, SessionStore) {
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
                service_tokens: Default::default(),
            }),
            config: Arc::new(config_file),
            adapter_registry: AdapterRegistry::new(),
            state_db: Some(pool.clone()),
            shutdown: Default::default(),
            metrics: None,
            permissions_cache: cache,
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

async fn spawn_gateway() -> (Harness, AuthConfig, SessionStore) {
    spawn_gateway_inner(None).await
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
        cache: None,
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
                service_tokens: Default::default(),
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

/// Boot the gateway with the resolver cache wired up, so admin mutations
/// can be observed to invalidate cached authz decisions. Thin wrapper over
/// [`spawn_gateway_inner`] — the only real difference from [`spawn_gateway`]
/// is the wired-in cache.
async fn spawn_gateway_with_cache() -> (Harness, PermissionsCache, AuthConfig, SessionStore) {
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool().await));
    // 60s TTL keeps the "before" cache entry fresh for the whole test — we
    // rely on the invalidation, not TTL expiry, to prove the drop.
    let cache = PermissionsCache::new(repo, Duration::from_secs(60));
    let (h, cfg, sessions) = spawn_gateway_inner(Some(cache.clone())).await;
    (h, cache, cfg, sessions)
}

/// Poll `cache.get_for` until the grant count reaches `want` or we exhaust
/// the retry budget. Invalidation runs on a `tokio::spawn`ed task (so a
/// client disconnect can't strand the write-lock cleanup), so the read
/// after the admin call races the invalidator — this helper waits it out.
async fn poll_cache_len(
    cache: &PermissionsCache,
    identity: &Identity,
    want: usize,
) -> Arc<Vec<db_mcp_gateway::config::Grant>> {
    let mut attempts = 0;
    loop {
        let grants = cache.get_for(identity).await.expect("cache load");
        if grants.len() == want || attempts >= 40 {
            return grants;
        }
        attempts += 1;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn latest_audit_action(pool: &PgPool, target_id: Uuid) -> Option<String> {
    latest_audit_for_target(pool, target_id)
        .await
        .map(|(action, _, _, _, _)| action)
}

/// **Cache invalidation on PATCH.** A cached authz decision for a user
/// must NOT survive a PATCH on that user's row. Group changes flip
/// constraint-merge results, and even email-only patches invalidate
/// because we never want the cache to lag a mutation admins observe.
///
/// Setup: seed a user via admin, warm the cache (0 grants), add a grant
/// out-of-band via the repo (bypasses the admin-endpoint invalidation),
/// then PATCH the user. If the PATCH fires the invalidation, the next
/// `get_for` reloads from the DB and sees the out-of-band grant.
#[tokio::test]
async fn patch_invalidates_cached_authz_for_user() {
    let (mut h, cache, auth_cfg, sessions) = spawn_gateway_with_cache().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-cache-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    // Seed target user via admin API so cache invalidation on the create
    // path is exercised alongside the eventual PATCH.
    let create: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "cache@example.com",
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

    let identity = Identity {
        session_id: SessionId::new(),
        user_sub: target_sub.clone(),
        user_email: "cache@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
    };

    // Warm the cache with the pre-patch state: no grants.
    let initial = cache.get_for(&identity).await.expect("cache warm");
    assert!(initial.is_empty(), "target user starts with no grants");

    // Add a database + grant directly via the repo. This intentionally
    // bypasses the admin endpoint's cache invalidation so we can prove
    // the PATCH below is what drops the stale entry.
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(h.pool.clone()));
    let db_row = repo
        .create_database(
            "prod",
            &format!("cache-app-{}", Uuid::new_v4().simple()),
            DbType::Postgres,
        )
        .await
        .expect("seed database");
    let db_id = db_row.id;
    let grant = repo
        .create_grant(
            target_id,
            GrantTarget::Specific { database_id: db_id },
            GrantAction::QueryRead,
            json!({ "row_limit": 100 }),
        )
        .await
        .expect("seed grant");

    // Cache still returns 0 — TTL is 60s and no invalidation has fired.
    let stale = cache.get_for(&identity).await.expect("cache still stale");
    assert!(
        stale.is_empty(),
        "cache must return the pre-warmed empty set until an invalidation fires"
    );

    // PATCH the user — this is the invalidation trigger under test.
    let resp = client()
        .patch(format!("{}/admin/v1/users/{}", h.base_url, target_id))
        .bearer_auth(&jwt)
        .json(&json!({ "user_email": "cache2@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Post-PATCH: the fire-and-forget invalidation lands, the next
    // `get_for` reloads from the DB, and the out-of-band grant appears.
    let after = poll_cache_len(&cache, &identity, 1).await;
    assert_eq!(
        after.len(),
        1,
        "PATCH must invalidate the cache entry; got {after:?}"
    );

    // Mutation audit row landed (belt-and-suspenders — CLAUDE.md #4).
    assert_eq!(
        latest_audit_action(&h.pool, target_id).await.as_deref(),
        Some("update"),
        "PATCH must write an update audit row"
    );

    // Cleanup: revoke the grant + drop the database we seeded directly.
    let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(grant.id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_grants WHERE id = $1")
        .bind(grant.id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(db_id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_databases WHERE id = $1")
        .bind(db_id)
        .execute(&h.pool)
        .await;
    h.cleanup().await;
}

/// **Cache invalidation on DELETE.** A soft-deleted user's cached grants
/// must not keep landing authz decisions until the TTL expires. Seed a
/// user + grant, warm the cache (sees the grant), DELETE the user, then
/// prove the cache reflects the deletion (loader returns empty for the
/// missing user).
#[tokio::test]
async fn delete_invalidates_cached_authz_for_user() {
    let (mut h, cache, auth_cfg, sessions) = spawn_gateway_with_cache().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let target_sub = format!("target-e2e-cache-del-{}", Uuid::new_v4().simple());
    h.track(target_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    // Seed target user + a real grant so the "before" cache state is
    // non-empty — that way the assertion after DELETE proves the entry
    // was dropped, not just that a fresh load happened to return empty.
    let create: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": target_sub,
            "user_email": "doomed@example.com",
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

    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(h.pool.clone()));
    let db_row = repo
        .create_database(
            "prod",
            &format!("del-cache-app-{}", Uuid::new_v4().simple()),
            DbType::Postgres,
        )
        .await
        .expect("seed database");
    let db_id = db_row.id;
    let grant = repo
        .create_grant(
            target_id,
            GrantTarget::Specific { database_id: db_id },
            GrantAction::QueryRead,
            json!({ "row_limit": 100 }),
        )
        .await
        .expect("seed grant");

    let identity = Identity {
        session_id: SessionId::new(),
        user_sub: target_sub.clone(),
        user_email: "doomed@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
    };

    // Warm cache — we should see the seeded grant.
    let initial = cache.get_for(&identity).await.expect("cache warm");
    assert_eq!(initial.len(), 1, "pre-delete cache carries the grant");

    // DELETE the user.
    let resp = client()
        .delete(format!("{}/admin/v1/users/{}", h.base_url, target_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Post-DELETE: the fire-and-forget invalidation lands, the next
    // `get_for` reloads, and the loader returns empty because the user
    // row is now soft-deleted (get_user_by_sub returns None).
    let after = poll_cache_len(&cache, &identity, 0).await;
    assert!(
        after.is_empty(),
        "DELETE must invalidate the cache entry; got {after:?}"
    );

    // Mutation audit row landed.
    assert_eq!(
        latest_audit_action(&h.pool, target_id).await.as_deref(),
        Some("delete"),
        "DELETE must write a delete audit row"
    );

    // Cleanup the seeded grant + database.
    let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(grant.id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_grants WHERE id = $1")
        .bind(grant.id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(db_id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_databases WHERE id = $1")
        .bind(db_id)
        .execute(&h.pool)
        .await;
    h.cleanup().await;
}

/// **Database mutations full-flush every user.** A PATCH or DELETE on
/// `/admin/v1/databases/:id` fires `PermissionsCache::invalidate_all` —
/// per-user invalidation isn't enough because a database row change (rename,
/// soft-delete) can reach any user whose grants reference it. This test
/// warms cached authz for two distinct identities, mutates the database
/// through both PATCH and DELETE, and proves both users' entries reload.
#[tokio::test]
async fn database_mutations_flush_all_cached_authz_for_all_users() {
    let (mut h, cache, auth_cfg, sessions) = spawn_gateway_with_cache().await;
    let admin_sub = format!("admin-e2e-{}", Uuid::new_v4().simple());
    let user_a_sub = format!("target-e2e-db-a-{}", Uuid::new_v4().simple());
    let user_b_sub = format!("target-e2e-db-b-{}", Uuid::new_v4().simple());
    h.track(user_a_sub.clone());
    h.track(user_b_sub.clone());

    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    // Seed two distinct users via the admin API.
    let user_a: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": user_a_sub,
            "user_email": "a@example.com",
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
    let user_a_id: Uuid = user_a["id"].as_str().unwrap().parse().unwrap();

    let user_b: Value = client()
        .post(format!("{}/admin/v1/users", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_sub": user_b_sub,
            "user_email": "b@example.com",
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
    let user_b_id: Uuid = user_b["id"].as_str().unwrap().parse().unwrap();

    // Seed the database via the admin API so PATCH/DELETE below hit the
    // real handler (and the real flush path).
    let db: Value = client()
        .post(format!("{}/admin/v1/databases", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "server": "prod",
            "db_name": format!("flush-app-{}", Uuid::new_v4().simple()),
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
    let db_id: Uuid = db["id"].as_str().unwrap().parse().unwrap();

    let identity_a = Identity {
        session_id: SessionId::new(),
        user_sub: user_a_sub.clone(),
        user_email: "a@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
    };
    let identity_b = Identity {
        session_id: SessionId::new(),
        user_sub: user_b_sub.clone(),
        user_email: "b@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
    };

    // Warm both users' cache entries with the pre-mutation state (0 grants).
    assert!(cache.get_for(&identity_a).await.unwrap().is_empty());
    assert!(cache.get_for(&identity_b).await.unwrap().is_empty());

    // Add a grant per user directly via the repo — bypasses admin API
    // invalidation so the DB-endpoint flush is what drops the stale entries.
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(h.pool.clone()));
    let grant_a = repo
        .create_grant(
            user_a_id,
            GrantTarget::Specific { database_id: db_id },
            GrantAction::QueryRead,
            json!({ "row_limit": 100 }),
        )
        .await
        .expect("seed grant a");
    let grant_b = repo
        .create_grant(
            user_b_id,
            GrantTarget::Specific { database_id: db_id },
            GrantAction::QueryRead,
            json!({ "row_limit": 100 }),
        )
        .await
        .expect("seed grant b");

    // Both users' caches still stale: TTL is 60s and no invalidation fired.
    assert!(cache.get_for(&identity_a).await.unwrap().is_empty());
    assert!(cache.get_for(&identity_b).await.unwrap().is_empty());

    // PATCH the database — `invalidate_all` should fire.
    let resp = client()
        .patch(format!("{}/admin/v1/databases/{}", h.base_url, db_id))
        .bearer_auth(&jwt)
        .json(&json!({ "db_name": format!("flush-renamed-{}", Uuid::new_v4().simple()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Post-PATCH: both users' entries drop, reload, and now see their grant.
    let a_after_patch = poll_cache_len(&cache, &identity_a, 1).await;
    assert_eq!(
        a_after_patch.len(),
        1,
        "database PATCH must reach user A: {a_after_patch:?}"
    );
    let b_after_patch = poll_cache_len(&cache, &identity_b, 1).await;
    assert_eq!(
        b_after_patch.len(),
        1,
        "database PATCH must reach user B: {b_after_patch:?}"
    );

    // Update audit row landed for the database (CLAUDE.md #4).
    assert_eq!(
        latest_audit_action(&h.pool, db_id).await.as_deref(),
        Some("update"),
        "PATCH must write an update audit row"
    );

    // DELETE the database — full flush again. The loader drops grants
    // pointing at soft-deleted db rows, so both users should reload to 0.
    let resp = client()
        .delete(format!("{}/admin/v1/databases/{}", h.base_url, db_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let a_after_delete = poll_cache_len(&cache, &identity_a, 0).await;
    assert!(
        a_after_delete.is_empty(),
        "database DELETE must reach user A: {a_after_delete:?}"
    );
    let b_after_delete = poll_cache_len(&cache, &identity_b, 0).await;
    assert!(
        b_after_delete.is_empty(),
        "database DELETE must reach user B: {b_after_delete:?}"
    );

    // Delete audit row landed for the database.
    assert_eq!(
        latest_audit_action(&h.pool, db_id).await.as_deref(),
        Some("delete"),
        "DELETE must write a delete audit row"
    );

    // Cleanup the seeded grants + database + their audit rows.
    for gid in [grant_a.id, grant_b.id] {
        let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
            .bind(gid)
            .execute(&h.pool)
            .await;
        let _ = sqlx::query("DELETE FROM permissions_grants WHERE id = $1")
            .bind(gid)
            .execute(&h.pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM permissions_audit WHERE target_id = $1")
        .bind(db_id)
        .execute(&h.pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions_databases WHERE id = $1")
        .bind(db_id)
        .execute(&h.pool)
        .await;
    h.cleanup().await;
}

/// `GET /admin/v1/users` used to return every live row (#136). It now takes a
/// bounded window, defaulting to `Page::DEFAULT_LIMIT` and clamping an
/// oversized ask rather than rejecting it.
#[tokio::test]
async fn list_honours_limit_query_param() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let admin_sub = format!("admin-page-{}", Uuid::new_v4().simple());
    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await;

    for _ in 0..3 {
        let target_sub = format!("page-{}", Uuid::new_v4().simple());
        h.track(target_sub.clone());
        let resp = client()
            .post(format!("{}/admin/v1/users", h.base_url))
            .bearer_auth(&jwt)
            .json(&json!({
                "user_sub": target_sub,
                "user_email": "page@example.com",
                "groups": ["engineers"],
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let page: Value = client()
        .get(format!("{}/admin/v1/users?limit=2", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        page.as_array().map(Vec::len),
        Some(2),
        "limit must bound the response: {page}"
    );

    // Clamped, not rejected — same treatment every other caller-supplied
    // bound gets in this gateway.
    let huge = client()
        .get(format!("{}/admin/v1/users?limit=999999999", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(huge.status(), StatusCode::OK);

    // A non-numeric limit is a genuine client mistake, not a clamp case.
    let bad = client()
        .get(format!("{}/admin/v1/users?limit=abc", h.base_url))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let err: Value = bad.json().await.unwrap();
    assert_eq!(err["error"]["code"], "invalid_request", "{err}");

    h.cleanup().await;
}
