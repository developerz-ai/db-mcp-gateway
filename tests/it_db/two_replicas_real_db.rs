//! Two gateway replicas on one state DB (plan 101 slice 13 step 8). Each
//! replica is a separately booted router with its own permissions cache,
//! session cache and refresh-token handle — what they share is only the
//! state DB, exactly as in a multi-replica deployment.
//!
//! - permissions revoke on A reaches B's cache over `LISTEN/NOTIFY`, far
//!   inside the cache TTL;
//! - a refresh token raced on both replicas has exactly one winner;
//! - both replicas' pruners running at once neither fail nor touch rows
//!   inside retention;
//! - a logout on A rejects the subject's sessions on B.
//!
//! `/authorize` → `/token` is NOT covered: pending flows and authorization
//! codes are in-process, so a login must stay on one replica (sticky
//! sessions, or one replica serving login).
//!
//! Requires the dev state DB (`bin/dev up`); run under the shared DB lock.

use std::sync::Arc;
use std::time::Duration;

use crate::common::audit::assert_audit_outcome;
use crate::common::cleanup::{
    delete_audit_calls, delete_permissions_audit, delete_permissions_grant, delete_permissions_user,
};
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, TestGateway};
use db_mcp_gateway::audit;
use db_mcp_gateway::auth::jwt;
use db_mcp_gateway::auth::oauth::{GrantIdentity, RefreshTokens};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::state::permissions::pg::{PgPermissionsRepo, notify};
use db_mcp_gateway::state::permissions::{PermissionsRepo, PermissionsSeed};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

const ADMIN_GROUP: &str = "db-mcp-gateway-admins";
const YAML: &str = "servers:
  - name: prod
    kind: postgres
    host: prod.example.invalid
    databases:
      - { name: app, role: ro, password: unused }
permissions: []
";
/// Long enough that only a delivered `NOTIFY` — never the TTL — can explain
/// replica B dropping a revoked grant within [`WAIT`].
const CACHE_TTL: Duration = Duration::from_secs(3600);
const WAIT: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_millis(25);
const SESSION_TTL: Duration = Duration::from_secs(600);

/// Boot one replica with its own permissions cache, subscribed to the
/// invalidation channel the way `startup::boot` wires it. Returns once the
/// listener is subscribed: a `NOTIFY` sent earlier would never reach it.
async fn replica(pool: &PgPool, admin: bool, refresh: RefreshTokens) -> TestGateway {
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
    let cache = PermissionsCache::new(repo.clone(), CACHE_TTL);
    let (subscribed, mut ready) = mpsc::unbounded_channel();
    let listener_cache = cache.clone();
    tokio::spawn(notify::listen(pool.clone(), move |change| {
        let cache = listener_cache.clone();
        let subscribed = subscribed.clone();
        async move {
            cache.apply(&change).await;
            let _ = subscribed.send(());
        }
    }));
    tokio::time::timeout(WAIT, ready.recv())
        .await
        .expect("permissions listener subscribes");

    let mut builder = GatewayBuilder::new(YAML)
        .repo(repo)
        .cache(cache)
        .refresh(refresh);
    if admin {
        builder = builder.admin(ADMIN_GROUP, true);
    }
    builder.spawn(pool.clone()).await
}

async fn bearer(gw: &TestGateway, sub: &str, groups: &[String]) -> String {
    let session = gw
        .sessions
        .create(sub, "replica@example.com", groups, SESSION_TTL, None)
        .await
        .expect("session row");
    jwt::issue(
        &gw.auth_config.session_signing_key,
        session.id,
        sub,
        SESSION_TTL,
    )
    .expect("jwt")
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(WAIT)
        .build()
        .expect("http client")
}

/// `list_servers` on `gw` as `bearer`: does the caller see `prod`?
async fn sees_prod(gw: &TestGateway, bearer: &str) -> bool {
    let body: Value = http()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(bearer)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "list_servers"}}))
        .send()
        .await
        .expect("gateway reachable")
        .json()
        .await
        .expect("JSON-RPC body");
    body["result"]["content"][0]["text"]
        .as_str()
        .expect("list_servers text content")
        .contains(r#""name":"prod""#)
}

/// Poll `sees_prod` until it equals `expected` or [`WAIT`] passes.
async fn eventually_sees_prod(gw: &TestGateway, bearer: &str, expected: bool) -> bool {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if sees_prod(gw, bearer).await == expected {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn delete_sessions(pool: &PgPool, sub: &str) {
    sqlx::query("DELETE FROM sessions WHERE user_sub = $1")
        .bind(sub)
        .execute(pool)
        .await
        .expect("cleanup sessions");
}

#[tokio::test]
async fn grant_revoked_on_one_replica_is_dropped_by_the_other() {
    let pool = state_pool().await;
    let a = replica(&pool, true, RefreshTokens::default()).await;
    let b = replica(&pool, false, RefreshTokens::default()).await;
    let repo = PgPermissionsRepo::new(pool.clone());

    let sub = format!("replica-grant-{}", Uuid::new_v4().simple());
    let admin_sub = format!("replica-admin-{}", Uuid::new_v4().simple());
    let user = repo
        .upsert_user(&sub, "replica@example.com", &[])
        .await
        .expect("seed user");
    let admin = bearer(&a, &admin_sub, &[ADMIN_GROUP.to_string()]).await;
    let caller = bearer(&a, &sub, &[]).await;

    let created: Value = http()
        .post(format!("{}/admin/v1/grants", a.url))
        .bearer_auth(&admin)
        .json(&json!({"user_id": user.id, "server": "prod",
                      "db_name_wildcard": true, "action": "schema_read"}))
        .send()
        .await
        .expect("admin reachable")
        .error_for_status()
        .expect("grant created")
        .json()
        .await
        .expect("grant body");
    let grant_id: Uuid = created["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("grant id");

    // B loads the grant into its cache and serves it.
    assert!(
        eventually_sees_prod(&b, &caller, true).await,
        "replica B never saw the new grant"
    );
    assert_audit_outcome(&pool, &sub, "list_servers", "success", "list_servers on B").await;

    let revoked = http()
        .delete(format!("{}/admin/v1/grants/{grant_id}", a.url))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("admin reachable");
    assert!(revoked.status().is_success(), "{}", revoked.status());

    assert!(
        eventually_sees_prod(&b, &caller, false).await,
        "replica B still serves a grant revoked on A {WAIT:?} later — \
         the NOTIFY never reached its cache (TTL is {CACHE_TTL:?})"
    );
    assert_audit_outcome(&pool, &sub, "list_servers", "success", "post-revoke call").await;

    delete_permissions_audit(&pool, grant_id).await;
    delete_permissions_grant(&pool, grant_id).await;
    delete_permissions_audit(&pool, user.id).await;
    delete_permissions_user(&pool, &sub).await;
    delete_audit_calls(&pool, &sub).await;
    delete_sessions(&pool, &sub).await;
    delete_sessions(&pool, &admin_sub).await;
}

async fn redeem(gw: &TestGateway, refresh_token: &str) -> (StatusCode, Value) {
    let response = http()
        .post(format!("{}/token", gw.url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .expect("gateway reachable");
    let status = response.status();
    (status, response.json().await.expect("OAuth JSON body"))
}

#[tokio::test]
async fn refresh_token_raced_on_two_replicas_has_one_winner() {
    let pool = state_pool().await;
    let store = || RefreshTokens::with_db(pool.clone(), Duration::from_secs(3600));
    let a = replica(&pool, false, store()).await;
    let b = replica(&pool, false, store()).await;

    let sub = format!("replica-refresh-{}", Uuid::new_v4().simple());
    let token = format!("race-{}", Uuid::new_v4().simple());
    let identity = GrantIdentity {
        sub: sub.clone(),
        email: "replica@example.com".to_string(),
        groups: Vec::new(),
    };
    store().insert(&token, identity).await.expect("seed chain");

    let (on_a, on_b) = tokio::join!(redeem(&a, &token), redeem(&b, &token));
    let outcomes = [on_a, on_b];
    let winners: Vec<&Value> = outcomes
        .iter()
        .filter(|(status, _)| *status == StatusCode::OK)
        .map(|(_, body)| body)
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one replica may rotate: {outcomes:?}"
    );
    let loser = outcomes
        .iter()
        .find(|(status, _)| *status != StatusCode::OK)
        .expect("one loser");
    assert_eq!(loser.0, StatusCode::BAD_REQUEST, "{loser:?}");
    assert_eq!(loser.1["error"], "invalid_grant");

    // The rotated token is a shared-DB chain: either replica redeems it.
    let rotated = winners[0]["refresh_token"]
        .as_str()
        .expect("rotated refresh_token");
    let (status, body) = redeem(&b, rotated).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    store().purge_for_sub(&sub).await;
    delete_sessions(&pool, &sub).await;
}

#[tokio::test]
async fn pruners_on_two_replicas_never_fail_or_touch_retained_rows() {
    // Separate pools: two replicas, two sets of connections.
    let (replica_a, replica_b) = (state_pool().await, state_pool().await);
    let sub = format!("replica-prune-{}", Uuid::new_v4().simple());
    // Three batches' worth, so the two runs overlap on the advisory lock.
    sqlx::query(
        "INSERT INTO audit_calls \
         (id, request_id, user_sub, user_email, tool, outcome, occurred_at) \
         SELECT gen_random_uuid(), gen_random_uuid()::text, $1, 'p@example.com', \
                'list_servers', 'success', \
                now() - interval '200 days' * (g > 0)::int \
         FROM generate_series(0, 12000) AS g",
    )
    .bind(&sub)
    .execute(&replica_a)
    .await
    .expect("seed backlog + one retained row");

    let (on_a, on_b) = tokio::join!(
        audit::pruner::run_once(&replica_a, 90),
        audit::pruner::run_once(&replica_b, 90),
    );
    let concurrent = on_a.expect("pruner on A") + on_b.expect("pruner on B");
    assert!(concurrent > 0, "neither replica pruned anything");
    // A replica that finds the lock taken stops; the next tick finishes.
    audit::pruner::run_once(&replica_a, 90)
        .await
        .expect("follow-up tick");

    let left: Vec<bool> = sqlx::query_scalar(
        "SELECT occurred_at > now() - interval '90 days' FROM audit_calls WHERE user_sub = $1",
    )
    .bind(&sub)
    .fetch_all(&replica_a)
    .await
    .expect("count survivors");
    assert_eq!(left, vec![true], "only the in-retention row survives");

    delete_audit_calls(&replica_a, &sub).await;
}

async fn ping_status(gw: &TestGateway, bearer: &str) -> StatusCode {
    http()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(bearer)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .expect("gateway reachable")
        .status()
}

#[tokio::test]
async fn logout_on_one_replica_rejects_the_subject_on_the_other() {
    let pool = state_pool().await;
    let a = replica(&pool, false, RefreshTokens::default()).await;
    let b = replica(&pool, false, RefreshTokens::default()).await;
    let sub = format!("replica-logout-{}", Uuid::new_v4().simple());
    let laptop = bearer(&a, &sub, &[]).await;
    let phone = bearer(&a, &sub, &[]).await;
    assert_eq!(ping_status(&b, &laptop).await, StatusCode::OK);

    let logout = http()
        .post(format!("{}/auth/logout", a.url))
        .bearer_auth(&laptop)
        .send()
        .await
        .expect("gateway reachable");
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);

    assert_eq!(ping_status(&a, &laptop).await, StatusCode::UNAUTHORIZED);
    // B never cached `phone`: it reads the revoked row straight away. A
    // session B did cache stays served for at most its session-cache TTL
    // (proved in `session_cache_real_db`).
    assert_eq!(ping_status(&b, &phone).await, StatusCode::UNAUTHORIZED);

    delete_sessions(&pool, &sub).await;
}
