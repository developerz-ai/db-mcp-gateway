//! Mysql parity tests for [`PermissionsRepo`] (#59).
//!
//! Mirrors `tests/permissions_repo_real_db.rs` against the
//! `permissions-mysql` service from `docker-compose.dev.yml`. The trait
//! contract is what's tested — the same assertions pass on either
//! backend, validating that callers don't need to know which is in use.

use db_mcp_gateway::state::permissions::mysql::MysqlPermissionsRepo;
use db_mcp_gateway::state::permissions::{DbType, GrantAction, GrantTarget, PermissionsRepo};
use db_mcp_gateway::state::{self};
use serde_json::json;
use uuid::Uuid;

fn mysql_dsn() -> String {
    std::env::var("PERMISSIONS_DB_DSN").unwrap_or_else(|_| {
        "mysql://permissions:permissions-dev-only@localhost:3307/permissions".to_string()
    })
}

async fn repo() -> MysqlPermissionsRepo {
    let pool = state::connect_permissions_mysql(&mysql_dsn(), 5)
        .await
        .expect("mysql permissions store up (run `bin/dev up`)");
    MysqlPermissionsRepo::new(pool)
}

fn unique_sub(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

/// Upsert + get-by-sub round-trip. Same contract as pg: the row exists
/// after upsert, the fields match what we sent.
#[tokio::test]
async fn upsert_then_get_by_sub_roundtrips() {
    let r = repo().await;
    let sub = unique_sub("mysql-upsert");
    let user = r
        .upsert_user(&sub, "a@example.com", &["engineers".to_string()])
        .await
        .expect("upsert ok");
    assert_eq!(user.user_sub, sub);
    assert_eq!(user.user_email, "a@example.com");
    assert_eq!(user.groups, vec!["engineers".to_string()]);

    let fetched = r.get_user_by_sub(&sub).await.expect("get ok");
    assert_eq!(fetched.as_ref().map(|u| u.user_sub.clone()), Some(sub));
}

/// Upsert on a live row updates in place (same id). Soft-deleted row +
/// new upsert mints a fresh id — the prior row stays as audit trail.
#[tokio::test]
async fn upsert_on_live_updates_in_place() {
    let r = repo().await;
    let sub = unique_sub("mysql-update");
    let first = r
        .upsert_user(&sub, "a@example.com", &["g1".to_string()])
        .await
        .expect("first upsert");
    let second = r
        .upsert_user(
            &sub,
            "a-changed@example.com",
            &["g1".to_string(), "g2".to_string()],
        )
        .await
        .expect("second upsert");
    assert_eq!(first.id, second.id, "live upsert keeps the same id");
    assert_eq!(second.user_email, "a-changed@example.com");
    assert_eq!(second.groups.len(), 2);
}

/// Soft delete + re-upsert mints a new id (partial-uniqueness emulation).
#[tokio::test]
async fn soft_delete_then_reupsert_mints_new_id() {
    let r = repo().await;
    let sub = unique_sub("mysql-reup");
    let first = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("first upsert");
    let deleted = r.soft_delete_user(first.id).await.expect("delete ok");
    assert!(deleted);

    let second = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("second upsert");
    assert_ne!(first.id, second.id, "post-delete upsert mints fresh id");
}

/// Create database + create grant for that database + list grants for
/// the user returns the grant we created. The headline resolver path.
#[tokio::test]
async fn create_grant_then_list_for_user() {
    let r = repo().await;
    let sub = unique_sub("mysql-grant");
    let user = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("user upsert");

    // Use a unique server name per test run so concurrent tests don't
    // collide on the live-uniqueness constraint.
    let db_label = format!("appdb-{}", Uuid::new_v4().simple());
    let db = r
        .create_database(&db_label, "app", DbType::Postgres)
        .await
        .expect("db create");

    let grant = r
        .create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            json!({ "row_limit": 1000 }),
        )
        .await
        .expect("grant create");

    let grants = r.list_grants_for_user(user.id).await.expect("list ok");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, grant.id);
    assert_eq!(grants[0].action, GrantAction::QueryRead);
    match &grants[0].target {
        GrantTarget::Specific { database_id } => assert_eq!(*database_id, db.id),
        other => panic!("expected Specific, got {other:?}"),
    }
}

/// Wildcard target round-trip — the XOR check on the storage side AND
/// the type-side mapping both accept the `Wildcard { server }` shape.
#[tokio::test]
async fn create_wildcard_grant_roundtrips() {
    let r = repo().await;
    let sub = unique_sub("mysql-wild");
    let user = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("user upsert");

    let grant = r
        .create_grant(
            user.id,
            GrantTarget::Wildcard {
                server: "prod".to_string(),
            },
            GrantAction::SchemaRead,
            json!({}),
        )
        .await
        .expect("wildcard grant create");

    let fetched = r
        .get_grant(grant.id)
        .await
        .expect("get ok")
        .expect("grant exists");
    match fetched.target {
        GrantTarget::Wildcard { server } => assert_eq!(server, "prod"),
        other => panic!("expected Wildcard, got {other:?}"),
    }
}

/// Revoke a grant; `list_grants_for_user` no longer returns it.
#[tokio::test]
async fn revoke_grant_hides_it_from_user_listing() {
    let r = repo().await;
    let sub = unique_sub("mysql-revoke");
    let user = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("user upsert");
    let grant = r
        .create_grant(
            user.id,
            GrantTarget::Wildcard {
                server: "staging".to_string(),
            },
            GrantAction::QueryRead,
            json!({}),
        )
        .await
        .expect("grant create");

    let revoked = r.revoke_grant(grant.id).await.expect("revoke ok");
    assert!(revoked);

    let live = r.list_grants_for_user(user.id).await.expect("list ok");
    assert!(
        !live.iter().any(|g| g.id == grant.id),
        "revoked grant must not appear in live listing"
    );
}

/// A revoked grant is invisible to `get_grant` too, not just the listings —
/// the admin read-before-write contract treats revoked as gone.
#[tokio::test]
async fn revoke_grant_hides_it_from_get() {
    let r = repo().await;
    let sub = unique_sub("mysql-getrevoke");
    let user = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("user upsert");
    let grant = r
        .create_grant(
            user.id,
            GrantTarget::Wildcard {
                server: format!("srv-{}", Uuid::new_v4().simple()),
            },
            GrantAction::QueryRead,
            json!({}),
        )
        .await
        .expect("grant create");

    assert!(r.get_grant(grant.id).await.expect("get ok").is_some());
    assert!(r.revoke_grant(grant.id).await.expect("revoke ok"));
    assert!(
        r.get_grant(grant.id).await.expect("get ok").is_none(),
        "revoked grant must not be returned by get_grant"
    );
}

/// `list_grants(_, Some(db))` returns only `Specific` grants on that database:
/// wildcard grants carry no `database_id` so the filter excludes them, and
/// revoked rows drop out entirely.
#[tokio::test]
async fn list_grants_database_filter_excludes_wildcards_and_revoked() {
    let r = repo().await;
    let sub = unique_sub("mysql-listfilter");
    let user = r
        .upsert_user(&sub, "a@example.com", &[])
        .await
        .expect("user upsert");

    let db_label = format!("appdb-{}", Uuid::new_v4().simple());
    let db = r
        .create_database(&db_label, "app", DbType::Postgres)
        .await
        .expect("db create");

    let specific = r
        .create_grant(
            user.id,
            GrantTarget::Specific { database_id: db.id },
            GrantAction::QueryRead,
            json!({}),
        )
        .await
        .expect("specific grant");

    // Wildcard grant on a server — shares no `database_id` column.
    r.create_grant(
        user.id,
        GrantTarget::Wildcard {
            server: format!("srv-{}", Uuid::new_v4().simple()),
        },
        GrantAction::SchemaRead,
        json!({}),
    )
    .await
    .expect("wildcard grant");

    let filtered = r
        .list_grants(Some(user.id), Some(db.id))
        .await
        .expect("list ok");
    assert_eq!(
        filtered.len(),
        1,
        "database_id filter must exclude wildcard grants"
    );
    assert_eq!(filtered[0].id, specific.id);

    // Revoking the specific grant empties the filtered listing (live rows only).
    assert!(r.revoke_grant(specific.id).await.expect("revoke ok"));
    let after = r
        .list_grants(Some(user.id), Some(db.id))
        .await
        .expect("list ok");
    assert!(
        after.is_empty(),
        "revoked grant must not appear in list_grants"
    );
}
