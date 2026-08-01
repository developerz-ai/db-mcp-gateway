//! Real-DB integration tests for the #49 resolver: loader + cache fed into
//! `authz::evaluate_effective`.
//!
//! Asserts the symmetric-merge contract (spec 12): YAML and DB grants are
//! interchangeable inputs, and the most-restrictive constraint wins on
//! overlap. Cache invalidation is also covered — admin API writes that bust
//! the entry must take effect on the next request.
//!
//! Boots against the dev state DB (`bin/dev up`); no mocking per CLAUDE.md.

use std::sync::Arc;
use std::time::Duration;

use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::authz::{
    Decision, PermissionsCache, can_see_server_effective, evaluate_effective,
    loader::load_db_grants_for,
};
use db_mcp_gateway::config::{Action, ConfigFile};
use db_mcp_gateway::state;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::state::permissions::{DbType, GrantAction, GrantTarget, PermissionsRepo};
use sqlx::PgPool;
use uuid::Uuid;

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

fn fresh(tag: &str) -> String {
    format!("{tag}-{}", Uuid::new_v4().simple())
}

fn identity_for(sub: &str, groups: &[&str]) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: sub.to_string(),
        user_email: format!("{sub}@example.com"),
        groups: groups.iter().map(|g| g.to_string()).collect(),
        issued_at: chrono::Utc::now(),
    }
}

async fn cleanup(pool: &PgPool, user_sub: &str, server: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM permissions_grants \
         WHERE user_id IN (SELECT id FROM permissions_users WHERE user_sub = $1) \
            OR database_id IN (SELECT id FROM permissions_databases WHERE server = $2)",
    )
    .bind(user_sub)
    .bind(server)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM permissions_databases WHERE server = $1")
        .bind(server)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM permissions_users WHERE user_sub = $1")
        .bind(user_sub)
        .execute(pool)
        .await?;
    Ok(())
}

#[tokio::test]
async fn loader_projects_specific_grant_into_config_grant_shape() {
    let p = pool().await;
    let sub = fresh("loader-spec");
    let server = fresh("loader-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::QueryRead,
        serde_json::json!({ "row_limit": 500, "statement_timeout_ms": 1000 }),
    )
    .await
    .unwrap();

    let id = identity_for(&sub, &[]);
    let grants = load_db_grants_for(&repo, &id).await.expect("load");
    assert_eq!(grants.len(), 1, "one Specific grant should round-trip");
    assert_eq!(grants[0].server, server);
    assert_eq!(grants[0].database, "app");
    assert_eq!(grants[0].action, Action::QueryRead);
    assert_eq!(grants[0].constraints.row_limit, Some(500));
    assert_eq!(grants[0].constraints.statement_timeout_ms, Some(1000));

    cleanup(&p, &sub, &server).await.expect("cleanup succeeds");
}

#[tokio::test]
async fn loader_drops_grants_whose_database_was_soft_deleted() {
    let p = pool().await;
    let sub = fresh("loader-drop");
    let server = fresh("loader-drop-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::QueryRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    // Soft-delete the database. The grant row stays — but the loader must
    // drop it (re-created namesake databases shouldn't silently inherit
    // old grants).
    assert!(repo.soft_delete_database(db.id).await.unwrap());

    let id = identity_for(&sub, &[]);
    let grants = load_db_grants_for(&repo, &id).await.expect("load");
    assert!(
        grants.is_empty(),
        "grant on a soft-deleted db must not surface, got {:?}",
        grants
    );

    cleanup(&p, &sub, &server).await.expect("cleanup succeeds");
}

#[tokio::test]
async fn loader_returns_empty_for_user_with_no_permissions_row() {
    let p = pool().await;
    let repo = PgPermissionsRepo::new(p.clone());
    // A user_sub that exists ONLY in the YAML world (e.g. brand-new SSO
    // user, no admin-API onboarding yet) gets an empty DB-grant set — NOT
    // an error. The YAML path still applies.
    let id = identity_for(&fresh("no-row-user"), &["devs"]);
    let grants = load_db_grants_for(&repo, &id).await.expect("load");
    assert!(grants.is_empty());
}

#[tokio::test]
async fn evaluate_effective_grants_via_db_with_no_yaml_match() {
    let p = pool().await;
    let sub = fresh("evdb");
    let server = fresh("evdb-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::QueryRead,
        serde_json::json!({ "row_limit": 100 }),
    )
    .await
    .unwrap();

    let id = identity_for(&sub, &[]); // no YAML group membership
    let db_grants = load_db_grants_for(&repo, &id).await.unwrap();

    // No YAML permissions, but DB grant matches → Allow.
    let decision = evaluate_effective(&id, Action::QueryRead, &server, "app", &[], &db_grants);
    let Decision::Allow { constraints } = decision else {
        panic!("expected Allow, got {decision:?}");
    };
    assert_eq!(constraints.row_limit, Some(100));

    cleanup(&p, &sub, &server).await.expect("cleanup succeeds");
}

#[tokio::test]
async fn evaluate_effective_merges_yaml_and_db_most_restrictive() {
    // YAML grants row_limit=10000; DB grant says row_limit=50. Symmetric
    // merge — the DB tightening must win without YAML being "primary".
    let p = pool().await;
    let sub = fresh("merge");
    let server = fresh("merge-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::QueryRead,
        serde_json::json!({ "row_limit": 50 }),
    )
    .await
    .unwrap();

    let yaml = format!(
        r#"
servers:
  - name: {server}
    kind: postgres
    host: x
    databases:
      - {{ name: app, role: ro, password: pw }}
permissions:
  - group: devs
    grants:
      - {{ server: {server}, database: app, action: query_read, constraints: {{ row_limit: 10000 }} }}
"#
    );
    let cfg = ConfigFile::from_yaml_str(&yaml).expect("yaml parses");

    let id = identity_for(&sub, &["devs"]);
    let db_grants = load_db_grants_for(&repo, &id).await.unwrap();

    let decision = evaluate_effective(
        &id,
        Action::QueryRead,
        &server,
        "app",
        &cfg.permissions,
        &db_grants,
    );
    let Decision::Allow { constraints } = decision else {
        panic!("expected Allow, got {decision:?}");
    };
    // 50 (DB) wins over 10_000 (YAML). Symmetric — swap the sources mentally
    // and the result is the same.
    assert_eq!(
        constraints.row_limit,
        Some(50),
        "DB tightening must win over a looser YAML grant"
    );

    cleanup(&p, &sub, &server).await.expect("cleanup succeeds");
}

#[tokio::test]
async fn can_see_server_effective_includes_db_grants() {
    let p = pool().await;
    let sub = fresh("see");
    let server_name = fresh("see-server");
    let repo = PgPermissionsRepo::new(p.clone());

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server_name, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::SchemaRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let yaml = format!(
        r#"
servers:
  - name: {server_name}
    kind: postgres
    host: x
    databases:
      - {{ name: app, role: ro, password: pw }}
"#
    );
    let cfg = ConfigFile::from_yaml_str(&yaml).expect("yaml parses");

    let id = identity_for(&sub, &[]); // no YAML group → YAML alone would deny
    let db_grants = load_db_grants_for(&repo, &id).await.unwrap();

    let server = cfg.servers.iter().find(|s| s.name == server_name).unwrap();
    assert!(
        can_see_server_effective(&id, server, &cfg.permissions, &db_grants),
        "DB grant on this server should make it visible even with no YAML match"
    );

    cleanup(&p, &sub, &server_name)
        .await
        .expect("cleanup succeeds");
}

#[tokio::test]
async fn cache_hits_avoid_db_round_trip_and_invalidate_busts_it() {
    let p = pool().await;
    let sub = fresh("cache");
    let server = fresh("cache-server");
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(p.clone()));

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::QueryRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let cache = PermissionsCache::new(repo.clone(), Duration::from_secs(60));
    let id = identity_for(&sub, &[]);

    let first = cache.get_for(&id).await.expect("first load");
    assert_eq!(first.len(), 1, "should see the single live grant");

    // Add a NEW grant directly via repo (simulates an admin API write that
    // hasn't invalidated yet). Cache is stale on purpose.
    let db2 = repo
        .create_database(&server, "warehouse", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific {
            database_id: db2.id,
        },
        GrantAction::QueryRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let second = cache.get_for(&id).await.expect("second load");
    assert_eq!(
        second.len(),
        1,
        "cache should serve the stale entry until invalidated"
    );
    assert!(
        Arc::ptr_eq(&first, &second),
        "second hit should return the cached Arc, not a fresh load"
    );

    // Admin API would call this after a write.
    cache.invalidate(&sub).await;
    let third = cache.get_for(&id).await.expect("third load");
    assert_eq!(third.len(), 2, "post-invalidate must reload from DB");

    cleanup(&p, &sub, &server).await.expect("cleanup succeeds");
}

/// Wait for a detached `tokio::spawn` invalidation task to observably run.
/// The spawned task takes a write lock; a `JoinHandle` isn't exposed, so we
/// poll instead. Bounded — a stuck task fails the test loudly.
async fn await_condition<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("invalidation task did not run within timeout");
}

#[tokio::test]
async fn spawn_invalidate_drops_the_targeted_users_entry() {
    let p = pool().await;
    let sub = fresh("spawn-inv");
    let server = fresh("spawn-inv-server");
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(p.clone()));

    let user = repo.upsert_user(&sub, "u@example.com", &[]).await.unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific { database_id: db.id },
        GrantAction::QueryRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let cache = PermissionsCache::new(repo.clone(), Duration::from_secs(60));
    let id = identity_for(&sub, &[]);

    let first = cache.get_for(&id).await.expect("first load");
    assert_eq!(first.len(), 1, "sanity: single grant loads");

    // Add a second grant behind the cache's back.
    let db2 = repo
        .create_database(&server, "warehouse", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user.id,
        GrantTarget::Specific {
            database_id: db2.id,
        },
        GrantAction::QueryRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    // Fire-and-forget via the canonical detach helper.
    let opt = Some(cache.clone());
    PermissionsCache::spawn_invalidate(&opt, Some(&sub));

    // After the spawned task lands, the next load must see both grants.
    await_condition(|| async {
        cache
            .get_for(&id)
            .await
            .map(|g| g.len() == 2)
            .unwrap_or(false)
    })
    .await;

    cleanup(&p, &sub, &server).await.expect("cleanup succeeds");
}

#[tokio::test]
async fn spawn_invalidate_is_a_noop_when_cache_is_none() {
    // YAML-only installs pass `None`; calling the helper must not panic and
    // must not spawn a task that would try to lock a missing cache.
    PermissionsCache::spawn_invalidate(&None, Some("any-sub"));
    // Also tolerate a missing user_sub even when the cache is wired.
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool().await));
    let cache = Some(PermissionsCache::new(repo, Duration::from_secs(60)));
    PermissionsCache::spawn_invalidate(&cache, None);
    // If we got here without panicking or hanging, the no-op contract holds.
}

#[tokio::test]
async fn spawn_invalidate_all_flushes_every_users_entry() {
    let p = pool().await;
    let sub_a = fresh("spawn-all-a");
    let sub_b = fresh("spawn-all-b");
    let server = fresh("spawn-all-server");
    let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(p.clone()));

    let user_a = repo
        .upsert_user(&sub_a, "a@example.com", &[])
        .await
        .unwrap();
    let user_b = repo
        .upsert_user(&sub_b, "b@example.com", &[])
        .await
        .unwrap();
    let db = repo
        .create_database(&server, "app", DbType::Postgres)
        .await
        .unwrap();
    for uid in [user_a.id, user_b.id] {
        repo.create_grant(
            uid,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            serde_json::json!({}),
        )
        .await
        .unwrap();
    }

    let cache = PermissionsCache::new(repo.clone(), Duration::from_secs(60));
    let id_a = identity_for(&sub_a, &[]);
    let id_b = identity_for(&sub_b, &[]);

    // Populate both entries.
    let a_first = cache.get_for(&id_a).await.expect("a first");
    let b_first = cache.get_for(&id_b).await.expect("b first");
    assert_eq!(a_first.len(), 1);
    assert_eq!(b_first.len(), 1);

    // Add a second grant for user A only, then spawn a full flush. Both
    // entries must reload — flush isn't selective.
    let db2 = repo
        .create_database(&server, "warehouse", DbType::Postgres)
        .await
        .unwrap();
    repo.create_grant(
        user_a.id,
        GrantTarget::Specific {
            database_id: db2.id,
        },
        GrantAction::QueryRead,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    let opt = Some(cache.clone());
    PermissionsCache::spawn_invalidate_all(&opt);

    await_condition(|| async {
        cache
            .get_for(&id_a)
            .await
            .map(|g| g.len() == 2)
            .unwrap_or(false)
    })
    .await;
    // User B's entry was flushed too; a reload returns a fresh Arc even
    // though the underlying grant set is unchanged.
    let b_second = cache.get_for(&id_b).await.expect("b second");
    assert!(
        !Arc::ptr_eq(&b_first, &b_second),
        "full flush must drop unaffected users' entries too"
    );

    cleanup(&p, &sub_a, &server).await.expect("cleanup a");
    cleanup(&p, &sub_b, &server).await.expect("cleanup b");
}

#[tokio::test]
async fn spawn_invalidate_all_is_a_noop_when_cache_is_none() {
    PermissionsCache::spawn_invalidate_all(&None);
    // No panic, no hang — contract holds.
}
