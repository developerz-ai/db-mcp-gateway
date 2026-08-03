//! Mysql parity tests for [`PermissionsRepo`] (#59).
//!
//! Mirrors `tests/permissions_repo_real_db.rs` against the
//! `permissions-mysql` service from `docker-compose.dev.yml`. The trait
//! contract is what's tested — the same assertions pass on either
//! backend, validating that callers don't need to know which is in use.

use db_mcp_gateway::state::permissions::mysql::MysqlPermissionsRepo;
use db_mcp_gateway::state::permissions::{DbType, GrantAction, GrantTarget, Page, PermissionsRepo};
use db_mcp_gateway::state::{self};
use serde_json::json;
use sqlx::MySqlPool;
use uuid::Uuid;

/// Page wide enough that a presence/absence assertion is really asking "is
/// this row in the table at all".
///
/// Mirrors `wide_page()` in `tests/permissions_repo_real_db.rs`. Listings are
/// ordered by `created_at` ascending, so the row a test just created is the
/// *last* one — exactly the row a narrow page drops once a dev DB accumulates
/// more than `Page::DEFAULT_LIMIT` rows across runs. These tests are not about
/// pagination; the ones that are pass an explicit `Page::new(..)`.
fn wide_page() -> Page {
    Page::new(Some(Page::MAX_LIMIT), None)
}

fn mysql_dsn() -> String {
    std::env::var("PERMISSIONS_DB_DSN").unwrap_or_else(|_| {
        "mysql://permissions:permissions-dev-only@localhost:3307/permissions".to_string()
    })
}

async fn pool() -> MySqlPool {
    state::connect_permissions_mysql(&mysql_dsn(), 5)
        .await
        .expect("mysql permissions store up (run `bin/dev up`)")
}

async fn repo() -> MysqlPermissionsRepo {
    MysqlPermissionsRepo::new(pool().await)
}

fn unique_sub(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

/// Hard-delete a seeded user plus every grant that touches them. Same rationale
/// as `cleanup_user` in the pg suite: the shared dev DB otherwise accumulates
/// rows across reruns, and the partial-uniqueness emulation lets soft-deleted
/// rows linger and inflate the table. `.expect(...)` so a cleanup failure fails
/// the test loudly instead of silently leaking rows — pg does the same.
async fn cleanup_user(pool: &MySqlPool, user_sub: &str) {
    sqlx::query(
        "DELETE FROM permissions_grants \
         WHERE user_id IN (SELECT id FROM permissions_users WHERE user_sub = ?)",
    )
    .bind(user_sub)
    .execute(pool)
    .await
    .expect("cleanup grants");
    sqlx::query("DELETE FROM permissions_users WHERE user_sub = ?")
        .bind(user_sub)
        .execute(pool)
        .await
        .expect("cleanup users");
}

/// Companion for `cleanup_user` — deletes everything a test seeded on a
/// per-test-unique `server` name (grants first for the FK, then the databases
/// themselves). `.expect(...)` for the same fail-loud reason as `cleanup_user`.
async fn cleanup_server(pool: &MySqlPool, server: &str) {
    sqlx::query(
        "DELETE FROM permissions_grants \
         WHERE database_id IN (SELECT id FROM permissions_databases WHERE server = ?)",
    )
    .bind(server)
    .execute(pool)
    .await
    .expect("cleanup grants for server");
    sqlx::query("DELETE FROM permissions_databases WHERE server = ?")
        .bind(server)
        .execute(pool)
        .await
        .expect("cleanup databases");
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
        .list_grants(Some(user.id), Some(db.id), Page::default())
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
        .list_grants(Some(user.id), Some(db.id), Page::default())
        .await
        .expect("list ok");
    assert!(
        after.is_empty(),
        "revoked grant must not appear in list_grants"
    );
}

/// Parity with pg's `get_user_by_sub_skips_soft_deleted`. Soft delete must
/// hide the row from both single-row lookup and the listing, and a second
/// delete must be a no-op.
#[tokio::test]
async fn get_user_by_sub_skips_soft_deleted() {
    let r = repo().await;
    let sub = unique_sub("mysql-getsoft");
    let user = r
        .upsert_user(&sub, "x@example.com", &[])
        .await
        .expect("create");

    assert!(
        r.get_user_by_sub(&sub).await.expect("get").is_some(),
        "live user should be found"
    );
    let before = r.list_users(wide_page()).await.expect("list before");
    assert!(before.iter().any(|u| u.id == user.id));

    assert!(
        r.soft_delete_user(user.id).await.expect("delete"),
        "delete should hit one row"
    );
    assert!(
        r.get_user_by_sub(&sub).await.expect("get").is_none(),
        "soft-deleted user must not surface"
    );
    let after = r.list_users(wide_page()).await.expect("list after");
    assert!(!after.iter().any(|u| u.id == user.id));
    assert!(
        !r.soft_delete_user(user.id).await.expect("redelete"),
        "second delete should affect 0 rows"
    );
}

/// Parity with pg's `database_crud_and_list_filters_soft_deleted`. Also the
/// query behind `permissions_databases_server_db_name_live_idx`: the loader
/// reads the live-database listing on every permissions-cache miss.
#[tokio::test]
async fn database_crud_and_list_filters_soft_deleted() {
    let r = repo().await;
    let server = format!("mysql-dbcrud-{}", Uuid::new_v4().simple());

    let pg_db = r
        .create_database(&server, "app", DbType::Postgres)
        .await
        .expect("create pg");
    let mysql_db = r
        .create_database(&server, "warehouse", DbType::Mysql)
        .await
        .expect("create mysql");
    assert_eq!(pg_db.db_type, DbType::Postgres);
    assert_eq!(mysql_db.db_type, DbType::Mysql);

    let listed = r.list_databases(wide_page()).await.expect("list");
    assert!(listed.iter().any(|d| d.id == pg_db.id));
    assert!(listed.iter().any(|d| d.id == mysql_db.id));

    let renamed = r
        .update_database(mysql_db.id, None, Some("warehouse-v2"), None)
        .await
        .expect("update")
        .expect("row exists");
    assert_eq!(renamed.db_name, "warehouse-v2");
    assert_eq!(renamed.server, server, "unset PATCH fields stay put");
    assert_eq!(renamed.db_type, DbType::Mysql);

    assert!(r.soft_delete_database(pg_db.id).await.expect("del"));
    let after = r.list_databases(wide_page()).await.expect("list2");
    assert!(
        !after.iter().any(|d| d.id == pg_db.id),
        "soft-deleted db must drop from list"
    );
    assert!(
        r.get_database(pg_db.id).await.expect("get").is_none(),
        "soft-deleted db must not be fetchable"
    );
    assert!(
        !r.soft_delete_database(pg_db.id).await.expect("redel"),
        "second delete should affect 0 rows"
    );
}

/// Parity with pg's `list_users_honours_limit_and_offset`. `Page::new(limit,
/// offset)` must actually bound and shift the window on the mysql backend too;
/// asserted against a wide-page baseline so sibling tests in the shared DB
/// can't make it flaky.
#[tokio::test]
async fn mysql_list_users_honours_limit_and_offset() {
    let p = pool().await;
    let r = MysqlPermissionsRepo::new(p.clone());
    // Retain the seeded subs for cleanup after assertions.
    let mut seeded_subs = Vec::with_capacity(3);
    for _ in 0..3 {
        let sub = unique_sub("mysql-page");
        r.upsert_user(&sub, "page@example.com", &[])
            .await
            .expect("seed user");
        seeded_subs.push(sub);
    }

    let wide = Page::new(Some(Page::MAX_LIMIT), None);
    let baseline = r.list_users(wide).await.expect("baseline");
    assert!(baseline.len() >= 3, "seeded at least three users");

    let first_two = r
        .list_users(Page::new(Some(2), None))
        .await
        .expect("limited");
    assert_eq!(first_two.len(), 2, "limit must bound the row count");
    assert_eq!(
        first_two.iter().map(|u| u.id).collect::<Vec<_>>(),
        baseline.iter().take(2).map(|u| u.id).collect::<Vec<_>>(),
        "first page must be the head of the full ordering"
    );

    let shifted = r
        .list_users(Page::new(Some(2), Some(1)))
        .await
        .expect("offset");
    assert_eq!(
        shifted.iter().map(|u| u.id).collect::<Vec<_>>(),
        baseline
            .iter()
            .skip(1)
            .take(2)
            .map(|u| u.id)
            .collect::<Vec<_>>(),
        "offset must shift the window by exactly that many rows"
    );

    for sub in &seeded_subs {
        cleanup_user(&p, sub).await;
    }
}

/// Parity with pg's `paging_covers_every_row_without_duplicates`. Walking the
/// full listing in windows must visit every seeded row without ever returning
/// the same id twice — the property a non-deterministic tiebreak on the mysql
/// `ORDER BY` would silently break.
#[tokio::test]
async fn mysql_paging_covers_every_row_without_duplicates() {
    let p = pool().await;
    let r = MysqlPermissionsRepo::new(p.clone());
    let mut seeded = Vec::new();
    let mut seeded_subs = Vec::new();
    for _ in 0..3 {
        let sub = unique_sub("mysql-cover");
        let user = r
            .upsert_user(&sub, "c@example.com", &[])
            .await
            .expect("seed user");
        seeded.push(user.id);
        seeded_subs.push(sub);
    }

    let mut walked = Vec::new();
    let mut offset = 0u32;
    loop {
        let page = r
            .list_users(Page::new(Some(2), Some(offset)))
            .await
            .expect("page");
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2, "page overran its limit");
        walked.extend(page.iter().map(|u| u.id));
        offset += 2;
    }

    let mut unique = walked.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        walked.len(),
        "a row was returned on more than one page"
    );
    for id in seeded {
        assert!(
            walked.contains(&id),
            "seeded user {id} was skipped by the page walk"
        );
    }

    for sub in &seeded_subs {
        cleanup_user(&p, sub).await;
    }
}

/// Parity with pg pagination coverage for `list_databases`: `limit` bounds the
/// row count, `offset` shifts the window by exactly that many rows.
///
/// Anchors on our seeded block instead of `baseline[0..N]`. `list_databases`
/// orders by `(server, db_name)`, so a concurrent test inserting a database
/// with a lexicographically-earlier `server` shifts absolute positions
/// mid-test. The seeded block itself is contiguous (same `server` + monotone
/// `db_name`) and only we can touch it, so `offset = block_start + k` is a
/// stable reference point once we've located `block_start`. We retry the
/// windowed reads a few times to survive a concurrent insert landing between
/// the `wide` snapshot and the offset read.
#[tokio::test]
async fn mysql_list_databases_honours_limit_and_offset() {
    let p = pool().await;
    let r = MysqlPermissionsRepo::new(p.clone());
    // Same server label for all three so a single `cleanup_server` sweeps them
    // (and any grant that happens to reference them).
    let server = format!("mysql-dbpage-{}", Uuid::new_v4().simple());
    let mut seeded_ids = Vec::with_capacity(3);
    for i in 0..3 {
        let db = r
            .create_database(&server, &format!("db-{i}"), DbType::Postgres)
            .await
            .expect("seed db");
        seeded_ids.push(db.id);
    }

    // limit alone: any page with `limit=2` must return at most two rows,
    // independent of surrounding DB state.
    let narrow = r
        .list_databases(Page::new(Some(2), None))
        .await
        .expect("limited");
    assert!(
        narrow.len() <= 2,
        "limit must bound the row count, got {}",
        narrow.len()
    );
    assert_eq!(
        narrow.len(),
        2,
        "the DB has ≥3 rows we seeded; expect a full page"
    );

    // offset: locate our block, then verify `offset = block_start + 1` skips
    // the first seeded row and returns the next two. Retry across concurrent
    // churn since the block's absolute position is not stable.
    let mut verified = false;
    let mut last_shifted: Vec<Uuid> = Vec::new();
    let mut last_expected: Vec<Uuid> = vec![seeded_ids[1], seeded_ids[2]];
    for _ in 0..5 {
        let wide = r
            .list_databases(Page::new(Some(Page::MAX_LIMIT), None))
            .await
            .expect("wide");
        let Some(block_start) = wide.iter().position(|d| d.server == server) else {
            continue;
        };
        let block_start = block_start as u32;
        // Confirm the block is still where we think it is before checking the
        // shifted window — a shift between these two reads would surface as an
        // anchor mismatch, and we simply retry.
        let anchor = r
            .list_databases(Page::new(Some(3), Some(block_start)))
            .await
            .expect("anchor");
        if anchor.iter().map(|d| d.id).collect::<Vec<_>>() != seeded_ids {
            continue;
        }
        let shifted = r
            .list_databases(Page::new(Some(2), Some(block_start + 1)))
            .await
            .expect("offset");
        last_shifted = shifted.iter().map(|d| d.id).collect();
        last_expected = vec![seeded_ids[1], seeded_ids[2]];
        if last_shifted == last_expected {
            verified = true;
            break;
        }
    }

    cleanup_server(&p, &server).await;
    assert!(
        verified,
        "offset must shift the window by exactly that many rows (last shifted {last_shifted:?}, expected {last_expected:?})",
    );
}

/// Parity with pg pagination coverage for `list_grants`. Seeds three grants
/// for one user, walks them in two-row pages, and asserts every seeded id
/// shows up once — same duplicate-free / total-ordering property as
/// `list_users`, since the filter path uses the same `ORDER BY`.
#[tokio::test]
async fn mysql_list_grants_pagination_covers_every_row_without_duplicates() {
    let p = pool().await;
    let r = MysqlPermissionsRepo::new(p.clone());
    let sub = unique_sub("mysql-grantpage");
    let user = r
        .upsert_user(&sub, "gp@example.com", &[])
        .await
        .expect("user upsert");
    let server = format!("mysql-grantpage-{}", Uuid::new_v4().simple());

    let mut seeded_grant_ids = Vec::with_capacity(3);
    for i in 0..3 {
        let db = r
            .create_database(&server, &format!("db-{i}"), DbType::Postgres)
            .await
            .expect("db create");
        let grant = r
            .create_grant(
                user.id,
                GrantTarget::Specific { database_id: db.id },
                GrantAction::QueryRead,
                json!({}),
            )
            .await
            .expect("grant create");
        seeded_grant_ids.push(grant.id);
    }

    let mut walked = Vec::new();
    let mut offset = 0u32;
    loop {
        let page = r
            .list_grants(Some(user.id), None, Page::new(Some(2), Some(offset)))
            .await
            .expect("page");
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2, "page overran its limit");
        walked.extend(page.iter().map(|g| g.id));
        offset += 2;
    }

    let mut unique = walked.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        walked.len(),
        "a grant was returned on more than one page"
    );
    for id in &seeded_grant_ids {
        assert!(
            walked.contains(id),
            "seeded grant {id} was skipped by the page walk"
        );
    }

    cleanup_user(&p, &sub).await;
    cleanup_server(&p, &server).await;
}

/// Parity with pg's `raw_insert_with_both_specific_and_wildcard_is_rejected_by_check`.
/// Mysql 8 enforces CHECK constraints, so the XOR is a real safety net behind
/// the typed `GrantTarget` — not just documentation — on this backend too.
#[tokio::test]
async fn raw_insert_with_both_specific_and_wildcard_is_rejected_by_check() {
    let p = pool().await;
    let r = MysqlPermissionsRepo::new(p.clone());
    let sub = unique_sub("mysql-xorcheck");
    let server = format!("mysql-xor-{}", Uuid::new_v4().simple());

    let user = r
        .upsert_user(&sub, "x@example.com", &[])
        .await
        .expect("user upsert");
    let db = r
        .create_database(&server, "app", DbType::Postgres)
        .await
        .expect("db create");

    // Both `database_id` AND `db_name_wildcard = TRUE` → must violate
    // permissions_grants_target_xor_wildcard_check.
    let err = sqlx::query(
        "INSERT INTO permissions_grants \
         (id, user_id, server, database_id, db_name_wildcard, action, constraints_json) \
         VALUES (?, ?, ?, ?, TRUE, 'query_read', '{}')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user.id.to_string())
    .bind(&server)
    .bind(db.id.to_string())
    .execute(&p)
    .await
    .expect_err("CHECK must reject the contradictory row");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("permissions_grants_target_xor_wildcard_check"),
        "expected XOR check violation, got: {msg}"
    );
}
