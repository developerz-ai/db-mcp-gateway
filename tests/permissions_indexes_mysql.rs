//! Query-plan regression tests for the mysql permissions store.
//!
//! `migrations-mysql/0001_permissions.sql` emulated pg's partial UNIQUE
//! indexes with generated `live_*` columns. Uniqueness worked; lookup did
//! not — mysql cannot serve `WHERE user_sub = ?` from an index on the
//! generated `live_user_sub` column, so the resolver's hot path
//! (`authz::loader::load_db_grants_for`) full-scanned `permissions_users`
//! on every permissions-cache miss. `0003_permissions_resolver_indexes.sql`
//! adds the missing base-column indexes.
//!
//! These assert on `EXPLAIN` against the real mysql from
//! `docker-compose.dev.yml` — the plan is the behavior under test, so there
//! is nothing to mock. Each test seeds enough rows that a full scan is not
//! accidentally the cheaper plan, then removes them again.
//!
//! The SQL below is duplicated from `src/state/permissions/mysql/` on
//! purpose: if a repo query is rewritten so it no longer matches an index,
//! the copy here stops matching the repo and the divergence is visible in
//! review.

use db_mcp_gateway::state::{self};
use serde_json::Value as JsonValue;
use sqlx::{MySqlPool, Row};
use uuid::Uuid;

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

/// The chosen plan for one table, reduced to the fields these tests assert on.
#[derive(Debug)]
struct Plan {
    /// `ALL` means full table scan — the state this migration fixes.
    access_type: String,
    key: Option<String>,
    using_filesort: bool,
}

/// `EXPLAIN FORMAT=JSON` rather than the tabular form: mysql sends tabular
/// EXPLAIN column names only at execute time, so sqlx (which names columns
/// from the prepare response) cannot address them. The JSON form is one
/// column, and gives `using_filesort` as a field instead of substring-matching
/// the `Extra` blob.
async fn explain(pool: &MySqlPool, query: &str) -> Plan {
    let json: String = sqlx::query(&format!("EXPLAIN FORMAT=JSON {query}"))
        .fetch_one(pool)
        .await
        .expect("explain runs")
        .try_get(0)
        .expect("explain returns one json column");
    let plan: JsonValue = serde_json::from_str(&json).expect("explain json parses");
    let table = find_table(&plan).unwrap_or_else(|| panic!("no table node in plan: {json}"));
    Plan {
        access_type: table["access_type"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        key: table["key"].as_str().map(str::to_string),
        // Absent when the query has no ORDER BY, which is also "not sorting".
        using_filesort: find_bool(&plan, "using_filesort").unwrap_or(false),
    }
}

/// The table node sits at `query_block.table`, or one level deeper under
/// `ordering_operation` when there is an ORDER BY. Find it by the field every
/// table node carries rather than hard-coding either shape.
fn find_table(value: &JsonValue) -> Option<&JsonValue> {
    if value.get("access_type").is_some() {
        return Some(value);
    }
    match value {
        JsonValue::Object(fields) => fields.values().find_map(find_table),
        JsonValue::Array(items) => items.iter().find_map(find_table),
        _ => None,
    }
}

fn find_bool(value: &JsonValue, name: &str) -> Option<bool> {
    if let Some(found) = value.get(name).and_then(JsonValue::as_bool) {
        return Some(found);
    }
    match value {
        JsonValue::Object(fields) => fields.values().find_map(|v| find_bool(v, name)),
        JsonValue::Array(items) => items.iter().find_map(|v| find_bool(v, name)),
        _ => None,
    }
}

/// Recursive-CTE seeding: one round trip instead of N inserts. Capped well
/// under mysql's default `cte_max_recursion_depth` of 1000.
const SEED_ROWS: u32 = 900;

#[tokio::test]
async fn get_user_by_sub_uses_the_user_sub_index() {
    let p = pool().await;
    let tag = format!("planseed-{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO permissions_users (id, user_sub, user_email, groups_json, deleted_at) \
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?) \
         SELECT UUID(), CONCAT(?, '-', i), 'seed@example.com', JSON_ARRAY(), \
                CASE WHEN i % 10 = 0 THEN NOW(6) ELSE NULL END \
         FROM n",
    )
    .bind(SEED_ROWS)
    .bind(&tag)
    .execute(&p)
    .await
    .expect("seed users");
    sqlx::query("ANALYZE TABLE permissions_users")
        .execute(&p)
        .await
        .expect("analyze");

    // Verbatim from `mysql::users::get_user_by_sub`, literal in place of the
    // bind so EXPLAIN sees the same shape the resolver issues.
    let plan = explain(
        &p,
        "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE user_sub = 'planseed-probe' AND deleted_at IS NULL",
    )
    .await;

    assert_ne!(
        plan.access_type, "ALL",
        "full scan on the hot path: {plan:?}"
    );
    assert_eq!(
        plan.key.as_deref(),
        Some("permissions_users_user_sub_live_idx"),
        "resolver lookup must read through the user_sub index, got {plan:?}"
    );

    sqlx::query("DELETE FROM permissions_users WHERE user_sub LIKE ?")
        .bind(format!("{tag}-%"))
        .execute(&p)
        .await
        .expect("cleanup users");
}

#[tokio::test]
async fn list_databases_uses_the_live_index_and_avoids_filesort() {
    let p = pool().await;
    let tag = format!("planseed-{}", Uuid::new_v4().simple());

    sqlx::query(
        "INSERT INTO permissions_databases (id, server, db_name, db_type, deleted_at) \
         WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?) \
         SELECT UUID(), CONCAT(?, '-', i), CONCAT('db-', i), 'postgres', \
                CASE WHEN i % 10 = 0 THEN NOW(6) ELSE NULL END \
         FROM n",
    )
    .bind(SEED_ROWS)
    .bind(&tag)
    .execute(&p)
    .await
    .expect("seed databases");
    sqlx::query("ANALYZE TABLE permissions_databases")
        .execute(&p)
        .await
        .expect("analyze");

    // Verbatim from `mysql::databases::list_databases` — the loader calls it
    // once per cache miss to resolve `Specific` grant targets.
    let plan = explain(
        &p,
        "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
         FROM permissions_databases \
         WHERE deleted_at IS NULL \
         ORDER BY server, db_name",
    )
    .await;

    assert_eq!(
        plan.key.as_deref(),
        Some("permissions_databases_server_db_name_live_idx"),
        "live-database listing must not full-scan, got {plan:?}"
    );
    assert!(
        !plan.using_filesort,
        "index must supply the (server, db_name) order, got {plan:?}"
    );

    sqlx::query("DELETE FROM permissions_databases WHERE server LIKE ?")
        .bind(format!("{tag}-%"))
        .execute(&p)
        .await
        .expect("cleanup databases");
}

/// Parity with pg's `permissions_grants_user_live_idx`. Already correct in
/// `0001` (plain composite key, not a generated column) — pinned here so the
/// third hot query can't regress the way the other two did.
#[tokio::test]
async fn list_grants_for_user_uses_the_user_index() {
    let p = pool().await;
    let plan = explain(
        &p,
        "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                constraints_json, created_at, updated_at, revoked_at \
         FROM permissions_grants \
         WHERE user_id = '00000000-0000-0000-0000-000000000000' AND revoked_at IS NULL \
         ORDER BY created_at",
    )
    .await;

    assert_eq!(
        plan.key.as_deref(),
        Some("permissions_grants_user_live_idx"),
        "per-user grant lookup must not full-scan, got {plan:?}"
    );
}
