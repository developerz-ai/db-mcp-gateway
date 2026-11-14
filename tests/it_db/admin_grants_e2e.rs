//! Integration tests for `/admin/v1/grants` (#54).
//!
//! Boots the gateway against the dev state DB (`bin/dev up`). Each test mints
//! its own session JWT directly (skipping OIDC) — mirrors the harness used by
//! `admin_users_e2e.rs` and `admin_databases_e2e.rs`.
//!
//! Acceptance from #54:
//!  - CRUD endpoints work for admin
//!  - XOR target enforced: exactly one of `database_id` (Specific) or
//!    `(server, db_name_wildcard: true)` (Wildcard); every other combination
//!    rejected
//!  - non-admin → 403
//!  - every write produces an audit row
//!  - **Live grant change is reflected on the next tool call without
//!    restart** — proven here by pre-warming the cache, POSTing a grant via
//!    the admin endpoint, and observing the cache sees the new grant on the
//!    next read
//!
//! Rollback proof is reused from #52 (`admin_users_e2e::
//! audit_write_failure_rolls_back_user_write`); the same `tx_*` helpers are
//! reused here unchanged, so the proof carries over without a duplicate test.

use std::sync::Arc;
use std::time::Duration;

use crate::common::cleanup::{
    delete_permissions_audit, delete_permissions_database, delete_permissions_grant,
    delete_permissions_user,
};
use crate::common::env::state_pool;
use crate::common::gateway::GatewayBuilder;
use db_mcp_gateway::auth::{AuthConfig, SessionStore, jwt};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::state::permissions::{DbType, PermissionsSeed, pg::PgPermissionsRepo};
use reqwest::StatusCode;
use secrecy::SecretSlice;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::Row;
use uuid::Uuid;

const ADMIN_GROUP: &str = "db-mcp-gateway-admins";

/// `prod` is the one declared server: the only legal wildcard target.
const GRANTS_YAML: &str = "servers:
  - name: prod
    kind: postgres
    description: E2E prod
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: hunter2 }
permissions: []
";

async fn mint_session(
    sessions: &SessionStore,
    signing_key: &SecretSlice<u8>,
    user_sub: &str,
    user_email: &str,
    groups: &[String],
) -> String {
    let session = sessions
        .create(user_sub, user_email, groups, Duration::from_secs(600), None)
        .await
        .expect("create session");
    jwt::issue(signing_key, session.id, user_sub, Duration::from_secs(600)).expect("issue JWT")
}

struct Harness {
    base_url: String,
    pool: PgPool,
    repo: Arc<PgPermissionsRepo>,
    cache: PermissionsCache,
    cleanup_grant_ids: Vec<Uuid>,
    cleanup_database_ids: Vec<Uuid>,
    cleanup_user_subs: Vec<String>,
}

impl Harness {
    fn track_grant(&mut self, id: Uuid) {
        self.cleanup_grant_ids.push(id);
    }

    fn track_database(&mut self, id: Uuid) {
        self.cleanup_database_ids.push(id);
    }

    fn track_user(&mut self, sub: impl Into<String>) {
        self.cleanup_user_subs.push(sub.into());
    }

    async fn cleanup(&self) {
        for id in &self.cleanup_grant_ids {
            delete_permissions_audit(&self.pool, *id).await;
            delete_permissions_grant(&self.pool, *id).await;
        }
        for id in &self.cleanup_database_ids {
            delete_permissions_audit(&self.pool, *id).await;
            delete_permissions_database(&self.pool, *id).await;
        }
        for sub in &self.cleanup_user_subs {
            let id_row = sqlx::query("SELECT id FROM permissions_users WHERE user_sub = $1")
                .bind(sub)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
            if let Some(row) = id_row {
                let id: Uuid = row.try_get("id").unwrap();
                delete_permissions_audit(&self.pool, id).await;
                let _ = sqlx::query("DELETE FROM permissions_grants WHERE user_id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await;
            }
            delete_permissions_user(&self.pool, sub).await;
        }
    }
}

async fn spawn_gateway() -> (Harness, AuthConfig, SessionStore) {
    let pool = state_pool().await;
    let repo = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let cache = PermissionsCache::new(repo.clone(), Duration::from_secs(60));
    let gw = GatewayBuilder::new(GRANTS_YAML)
        .admin(ADMIN_GROUP, true)
        .repo(repo.clone())
        .cache(cache.clone())
        .spawn(pool)
        .await;
    (
        Harness {
            base_url: gw.url,
            pool: gw.state_db,
            repo,
            cache,
            cleanup_grant_ids: Vec::new(),
            cleanup_database_ids: Vec::new(),
            cleanup_user_subs: Vec::new(),
        },
        gw.auth_config,
        gw.sessions,
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
         WHERE target_id = $1 AND target_type = 'grant' \
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

/// Seed a user + a database directly via the repo so tests can target real
/// rows without driving the full admin endpoints.
async fn seed_target_user_and_db(h: &mut Harness) -> (Uuid, Uuid, String) {
    let user_sub = format!("target-grants-e2e-{}", Uuid::new_v4().simple());
    let user = h
        .repo
        .upsert_user(&user_sub, "target@example.com", &["engineers".to_string()])
        .await
        .expect("seed user");
    h.track_user(user_sub.clone());

    let db = h
        .repo
        .create_database(
            "prod",
            &format!("app-{}", Uuid::new_v4().simple()),
            DbType::Postgres,
        )
        .await
        .expect("seed database");
    h.track_database(db.id);

    (user.id, db.id, user_sub)
}

async fn admin_jwt(sessions: &SessionStore, auth_cfg: &AuthConfig, h: &mut Harness) -> String {
    let admin_sub = format!("admin-grants-e2e-{}", Uuid::new_v4().simple());
    h.track_user(admin_sub.clone());
    mint_session(
        sessions,
        &auth_cfg.session_signing_key,
        &admin_sub,
        "admin@example.com",
        &[ADMIN_GROUP.to_string()],
    )
    .await
}

#[tokio::test]
async fn admin_creates_specific_grant_and_audit_recorded() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id,
            "database_id": db_id,
            "action": "query_read",
            "constraints": { "row_limit": 1000 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(id);
    assert_eq!(body["database_id"], db_id.to_string());
    assert_eq!(body["db_name_wildcard"], false);
    assert_eq!(body["action"], "query_read");
    assert!(
        body.get("server").is_none(),
        "specific grant must not carry server"
    );

    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "create");
    assert!(audit.1.is_none());
    assert_eq!(audit.2.as_ref().unwrap()["action"], "query_read");

    h.cleanup().await;
}

#[tokio::test]
async fn admin_creates_wildcard_grant_and_audit_recorded() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, _, _) = seed_target_user_and_db(&mut h).await;

    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id,
            "server": "prod",
            "db_name_wildcard": true,
            "action": "schema_read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: Value = resp.json().await.unwrap();
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(id);
    assert_eq!(body["server"], "prod");
    assert_eq!(body["db_name_wildcard"], true);
    assert!(
        body.get("database_id").is_none(),
        "wildcard grant must not carry database_id"
    );

    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "create");

    h.cleanup().await;
}

/// **XOR enforcement.** Every illegal target combination must be rejected
/// with `invalid_request` — both fields set, neither set, mismatched wildcard
/// flag. The DB CHECK is the safety net; this guarantees the handler never
/// even reaches the storage layer on these inputs.
#[tokio::test]
async fn xor_target_violations_are_rejected() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let bad_bodies = vec![
        // both target fields set
        json!({
            "user_id": user_id, "database_id": db_id,
            "server": "prod", "db_name_wildcard": true,
            "action": "query_read",
        }),
        // neither target field set
        json!({ "user_id": user_id, "action": "query_read" }),
        // database_id set but db_name_wildcard: true
        json!({
            "user_id": user_id, "database_id": db_id,
            "db_name_wildcard": true,
            "action": "query_read",
        }),
        // server set but db_name_wildcard absent (or false)
        json!({
            "user_id": user_id, "server": "prod",
            "action": "query_read",
        }),
        // server set with db_name_wildcard: false
        json!({
            "user_id": user_id, "server": "prod",
            "db_name_wildcard": false,
            "action": "query_read",
        }),
    ];

    for body in bad_bodies {
        let resp = client()
            .post(format!("{}/admin/v1/grants", h.base_url))
            .bearer_auth(&jwt)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "XOR violation must be rejected; sent {body}"
        );
        let err: Value = resp.json().await.unwrap();
        assert_eq!(err["error"]["code"], "invalid_request");
    }

    h.cleanup().await;
}

#[tokio::test]
async fn unknown_action_is_rejected() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "query_reed",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let err: Value = resp.json().await.unwrap();
    assert!(
        err["error"]["message"].as_str().unwrap().contains("action"),
        "error must name the field; got {err}"
    );

    h.cleanup().await;
}

/// A reference to a missing user or database must surface as
/// `invalid_request` (400) — client-correctable input, not a gateway fault.
#[tokio::test]
async fn create_grant_with_unknown_user_or_database_is_400() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    // Unknown user_id → FK violation on permissions_grants.user_id.
    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": Uuid::new_v4(),
            "database_id": db_id,
            "action": "query_read",
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
            .contains("invalid grant reference"),
        "dead reference must surface a stable message; got {err}"
    );

    // Unknown database_id → FK violation on permissions_grants.database_id.
    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id,
            "database_id": Uuid::new_v4(),
            "action": "query_read",
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
            .contains("invalid grant reference"),
        "dead reference must surface a stable message; got {err}"
    );

    h.cleanup().await;
}

#[tokio::test]
async fn patch_attempting_to_change_target_is_rejected() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let create: Value = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "query_read",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(grant_id);

    // Target fields aren't in UpdateGrantRequest — deny_unknown_fields → 400.
    let resp = client()
        .patch(format!("{}/admin/v1/grants/{}", h.base_url, grant_id))
        .bearer_auth(&jwt)
        .json(&json!({ "database_id": Uuid::new_v4() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    h.cleanup().await;
}

#[tokio::test]
async fn patch_updates_action_and_constraints_and_audits() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let create: Value = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "schema_read",
            "constraints": { "row_limit": 50000 },
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(grant_id);

    let resp = client()
        .patch(format!("{}/admin/v1/grants/{}", h.base_url, grant_id))
        .bearer_auth(&jwt)
        .json(&json!({
            "action": "query_read",
            "constraints": { "row_limit": 100, "require_reason": true },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["action"], "query_read");
    assert_eq!(v["constraints"]["row_limit"], 100);

    let audit = latest_audit_for_target(&h.pool, grant_id)
        .await
        .expect("audit");
    assert_eq!(audit.0, "update");
    assert_eq!(audit.1.as_ref().unwrap()["action"], "schema_read");
    assert_eq!(audit.2.as_ref().unwrap()["action"], "query_read");

    h.cleanup().await;
}

#[tokio::test]
async fn delete_revokes_and_audits() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let create: Value = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "query_read",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(grant_id);

    let resp = client()
        .delete(format!("{}/admin/v1/grants/{}", h.base_url, grant_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = client()
        .get(format!("{}/admin/v1/grants/{}", h.base_url, grant_id))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let audit = latest_audit_for_target(&h.pool, grant_id)
        .await
        .expect("audit");
    assert_eq!(audit.0, "delete");
    assert!(audit.2.is_none(), "delete row must omit after");

    h.cleanup().await;
}

#[tokio::test]
async fn list_filter_by_user_id() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_a_id, db_id, _) = seed_target_user_and_db(&mut h).await;
    let (user_b_id, _, _) = seed_target_user_and_db(&mut h).await;

    for user_id in [user_a_id, user_b_id] {
        let v: Value = client()
            .post(format!("{}/admin/v1/grants", h.base_url))
            .bearer_auth(&jwt)
            .json(&json!({
                "user_id": user_id, "database_id": db_id,
                "action": "query_read",
            }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let id: Uuid = v["id"].as_str().unwrap().parse().unwrap();
        h.track_grant(id);
    }

    let list: Vec<Value> = client()
        .get(format!(
            "{}/admin/v1/grants?user_id={}",
            h.base_url, user_a_id
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        list.iter().all(|g| g["user_id"] == user_a_id.to_string()),
        "filter returned grants for a different user; got {list:?}"
    );
    assert!(!list.is_empty(), "filter dropped all matches");

    h.cleanup().await;
}

/// A typo in a `GET /admin/v1/grants` query key (e.g. `usr_id` instead of
/// `user_id`) must return `invalid_request` (400) rather than silently
/// listing every grant. Regression guard for the flattened-PageQuery bug:
/// `#[serde(deny_unknown_fields)]` does not fire through `#[serde(flatten)]`,
/// so `ListGrantsQuery` has to hold `limit`/`offset` inline for the unknown-
/// field rejection to actually work.
#[tokio::test]
async fn list_rejects_unknown_query_key() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;

    let resp = client()
        .get(format!(
            "{}/admin/v1/grants?usr_id={}",
            h.base_url,
            Uuid::new_v4()
        ))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "unknown query key must be rejected, not silently ignored"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");

    h.cleanup().await;
}

/// **Headline acceptance.** A grant change made via the admin API must show
/// up on the next resolver lookup without a restart. Pre-warm the cache,
/// POST a grant, then read through the cache again — the new grant must
/// appear. This is the cache-invalidation hook's only purpose.
#[tokio::test]
async fn live_grant_change_invalidates_cache_for_user() {
    use db_mcp_gateway::auth::{Identity, SessionId};

    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, user_sub) = seed_target_user_and_db(&mut h).await;

    let identity = Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.clone(),
        user_email: "target@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
        kind: db_mcp_gateway::auth::IdentityKind::Sso,
    };

    // Pre-warm the cache for this user — observed grants: 0.
    let initial = h.cache.get_for(&identity).await.expect("cache load");
    assert!(initial.is_empty(), "user starts with no grants");

    // Admin POST a grant.
    let create: Value = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "query_read",
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id: Uuid = create["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(grant_id);

    // Read through the cache again — must see the new grant. The
    // invalidation fires post-commit on a `tokio::spawn`ed task (so a
    // client disconnect can't strand the write-lock cleanup), so poll
    // briefly for the entry drop rather than assuming a single read wins
    // the race with the invalidator.
    let mut attempts = 0;
    let after = loop {
        let grants = h
            .cache
            .get_for(&identity)
            .await
            .expect("cache load post-invalidate");
        if grants.len() == 1 || attempts >= 40 {
            break grants;
        }
        attempts += 1;
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        after.len(),
        1,
        "post-grant cache read must see the new grant; got {after:?}"
    );

    h.cleanup().await;
}

#[tokio::test]
async fn non_admin_gets_403_and_no_writes() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    let nonadmin_sub = format!("nonadmin-grants-e2e-{}", Uuid::new_v4().simple());
    h.track_user(nonadmin_sub.clone());
    let jwt = mint_session(
        &sessions,
        &auth_cfg.session_signing_key,
        &nonadmin_sub,
        "rando@example.com",
        &["engineers".to_string()],
    )
    .await;

    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(&jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "query_read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["code"], "forbidden",
        "403 must carry stable code; got {body}"
    );

    // No grant row.
    let n: i64 = sqlx::query("SELECT COUNT(*) FROM permissions_grants WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(n, 0, "non-admin 403 must not insert any grant");

    // No `permissions_audit` row for this caller. The middleware records the
    // denial via structured tracing (spec 07) but must NOT write to
    // `permissions_audit` — that table requires a real actor_id FK, and
    // upsert-on-deny would let any caller seed a row by probing /admin/*.
    let audit_n: i64 = sqlx::query(
        "SELECT COUNT(*) FROM permissions_audit WHERE actor_email = 'rando@example.com'",
    )
    .fetch_one(&h.pool)
    .await
    .unwrap()
    .try_get(0)
    .unwrap();
    assert_eq!(audit_n, 0, "non-admin 403 must not write any audit row");

    // No `permissions_users` row for the non-admin caller.
    let user_exists: bool =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM permissions_users WHERE user_sub = $1)")
            .bind(&nonadmin_sub)
            .fetch_one(&h.pool)
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
    assert!(
        !user_exists,
        "non-admin 403 must not seed a permissions_users row for the caller"
    );

    h.cleanup().await;
}

#[tokio::test]
async fn anonymous_gets_401() {
    let (h, _, _) = spawn_gateway().await;
    let resp = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .json(&json!({
            "user_id": Uuid::new_v4(), "database_id": Uuid::new_v4(),
            "action": "query_read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// POST a specific grant for a freshly seeded user/database; returns its id.
async fn create_specific_grant(h: &mut Harness, jwt: &str, constraints: Value) -> Uuid {
    let (user_id, db_id, _) = seed_target_user_and_db(h).await;
    let v: Value = client()
        .post(format!("{}/admin/v1/grants", h.base_url))
        .bearer_auth(jwt)
        .json(&json!({
            "user_id": user_id, "database_id": db_id,
            "action": "query_read", "constraints": constraints,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    h.track_grant(id);
    id
}

async fn patch_grant(h: &Harness, jwt: &str, id: Uuid, body: Value) -> reqwest::Response {
    client()
        .patch(format!("{}/admin/v1/grants/{}", h.base_url, id))
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .unwrap()
}

/// **No silent loosening.** A PATCH naming only `row_limit` keeps
/// `require_reason` and `statement_timeout_ms`; an explicit `null` clears
/// exactly the key it names.
#[tokio::test]
async fn patch_merges_per_key_and_never_drops_unnamed_constraints() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let initial = json!({ "require_reason": true, "row_limit": 500, "statement_timeout_ms": 2000 });
    let id = create_specific_grant(&mut h, &jwt, initial).await;

    let resp = patch_grant(&h, &jwt, id, json!({ "constraints": { "row_limit": 100 } })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: Value = resp.json().await.unwrap();
    assert_eq!(v["constraints"]["row_limit"], 100);
    assert_eq!(v["constraints"]["require_reason"], true, "unnamed key kept");
    assert_eq!(v["constraints"]["statement_timeout_ms"], 2000);

    let body = json!({ "constraints": { "statement_timeout_ms": null } });
    let v: Value = patch_grant(&h, &jwt, id, body).await.json().await.unwrap();
    assert!(v["constraints"]["statement_timeout_ms"].is_null());
    assert_eq!(v["constraints"]["require_reason"], true);
    assert_eq!(v["constraints"]["row_limit"], 100);

    h.cleanup().await;
}

/// A stale `expected_updated_at` is a 409 and changes nothing.
#[tokio::test]
async fn patch_with_stale_precondition_is_409() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let id = create_specific_grant(&mut h, &jwt, json!({ "row_limit": 10 })).await;

    let body = json!({
        "constraints": { "row_limit": 5 },
        "expected_updated_at": "2000-01-01T00:00:00Z",
    });
    let resp = patch_grant(&h, &jwt, id, body).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let err: Value = resp.json().await.unwrap();
    assert_eq!(err["error"]["code"], "conflict");
    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "create", "a refused PATCH writes no audit row");

    h.cleanup().await;
}

/// Concurrent PATCHes serialise on the grant row: every request applies and
/// the audit rows form an unbroken chain, `after[n] == before[n + 1]`.
#[tokio::test]
async fn concurrent_patches_leave_a_continuous_audit_chain() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let id = create_specific_grant(&mut h, &jwt, json!({ "row_limit": 1000 })).await;

    let patches = (1..=8u32).map(|n| {
        let body = json!({ "constraints": { "row_limit": n } });
        patch_grant(&h, &jwt, id, body)
    });
    for resp in futures::future::join_all(patches).await {
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let rows = sqlx::query(
        "SELECT before, after FROM permissions_audit \
         WHERE target_id = $1 AND target_type = 'grant' AND action = 'update' ORDER BY id",
    )
    .bind(id)
    .fetch_all(&h.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 8);
    let chain: Vec<(Value, Value)> = rows
        .iter()
        .map(|r| (r.get("before"), r.get("after")))
        .collect();
    for pair in chain.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "audit chain broken");
    }

    h.cleanup().await;
}

/// A wildcard must name a server the config declares: `*` and unknown
/// names are 400 and write nothing.
#[tokio::test]
async fn wildcard_on_star_or_undeclared_server_is_400() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, _, _) = seed_target_user_and_db(&mut h).await;

    for server in ["*", "staging"] {
        let resp = client()
            .post(format!("{}/admin/v1/grants", h.base_url))
            .bearer_auth(&jwt)
            .json(&json!({
                "user_id": user_id, "server": server,
                "db_name_wildcard": true, "action": "query_read",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "server {server:?}");
    }
    let n: i64 = sqlx::query("SELECT COUNT(*) FROM permissions_grants WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0);

    h.cleanup().await;
}

/// A grant cannot attach to a soft-deleted user or database.
#[tokio::test]
async fn grant_on_soft_deleted_user_or_database_is_400() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;
    let (live_user, deleted_db, _) = seed_target_user_and_db(&mut h).await;
    assert!(h.repo.soft_delete_user(user_id).await.unwrap());
    assert!(h.repo.soft_delete_database(deleted_db).await.unwrap());

    for (user, db) in [(user_id, db_id), (live_user, deleted_db)] {
        let resp = client()
            .post(format!("{}/admin/v1/grants", h.base_url))
            .bearer_auth(&jwt)
            .json(&json!({ "user_id": user, "database_id": db, "action": "query_read" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let err: Value = resp.json().await.unwrap();
        assert_eq!(err["error"]["code"], "invalid_request");
    }

    h.cleanup().await;
}

/// Slice 05 step 8: a zero bound would disable the limit, not tighten it —
/// POST and PATCH reject `row_limit: 0` / `statement_timeout_ms: 0` with 400
/// and write nothing.
#[tokio::test]
async fn zero_row_limit_or_timeout_is_400() {
    let (mut h, auth_cfg, sessions) = spawn_gateway().await;
    let jwt = admin_jwt(&sessions, &auth_cfg, &mut h).await;
    let (user_id, db_id, _) = seed_target_user_and_db(&mut h).await;

    for constraints in [
        json!({ "row_limit": 0 }),
        json!({ "statement_timeout_ms": 0 }),
    ] {
        let resp = client()
            .post(format!("{}/admin/v1/grants", h.base_url))
            .bearer_auth(&jwt)
            .json(&json!({
                "user_id": user_id, "database_id": db_id,
                "action": "query_read", "constraints": constraints,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{constraints}");
        let err: Value = resp.json().await.unwrap();
        assert_eq!(err["error"]["code"], "invalid_request");
    }
    let n: i64 = sqlx::query("SELECT COUNT(*) FROM permissions_grants WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&h.pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "a refused POST writes no grant");

    let id = create_specific_grant(&mut h, &jwt, json!({ "row_limit": 10 })).await;
    let body = json!({ "constraints": { "statement_timeout_ms": 0 } });
    let resp = patch_grant(&h, &jwt, id, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let audit = latest_audit_for_target(&h.pool, id).await.expect("audit");
    assert_eq!(audit.0, "create", "a refused PATCH writes no audit row");

    h.cleanup().await;
}
