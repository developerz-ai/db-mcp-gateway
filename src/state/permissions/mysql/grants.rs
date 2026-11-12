//! Grant CRUD operations for the MySQL permissions store.

use sqlx::MySqlPool;
use uuid::Uuid;

use super::super::{LiveGrant, Page, PermissionsGrant, RepoError};
use super::rows::{grant_from_row, live_grant_from_row};

#[cfg(any(test, feature = "test-support"))]
pub(super) async fn create_grant(
    pool: &MySqlPool,
    user_id: Uuid,
    target: super::super::GrantTarget,
    action: super::super::GrantAction,
    constraints: serde_json::Value,
) -> Result<PermissionsGrant, RepoError> {
    let (server, database_id, wildcard) = target.columns();
    let new_id = Uuid::new_v4();
    // INSERT + reread in one transaction: the caller always gets back the row it
    // just wrote. A post-insert read failure on the pool would otherwise surface
    // as an error even though the grant committed — retrying the POST would then
    // mint a second live grant.
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO permissions_grants \
         (id, user_id, server, database_id, db_name_wildcard, action, constraints_json, \
          created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, NOW(6), NOW(6))",
    )
    .bind(new_id.to_string())
    .bind(user_id.to_string())
    .bind(server)
    .bind(database_id.map(|id| id.to_string()))
    .bind(wildcard)
    .bind(action.as_db_str())
    .bind(&constraints)
    .execute(&mut *tx)
    .await?;
    let row = grant_by_id(&mut *tx, new_id)
        .await?
        .ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))?;
    tx.commit().await?;
    Ok(row)
}

/// Fetch a live grant by id on any executor (pool or open transaction). Shared
/// by the atomic create/update paths so the reread sees the write they just
/// made without leaving the transaction.
async fn grant_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<PermissionsGrant>, RepoError>
where
    E: sqlx::Executor<'e, Database = sqlx::MySql>,
{
    let row = sqlx::query(
        "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                constraints_json, created_at, updated_at, revoked_at \
         FROM permissions_grants \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id.to_string())
    .fetch_optional(executor)
    .await?;
    row.map(|r| grant_from_row(&r)).transpose()
}

#[cfg(any(test, feature = "test-support"))]
pub(super) async fn list_grants_for_user(
    pool: &MySqlPool,
    user_id: Uuid,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    let rows = sqlx::query(
        "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                constraints_json, created_at, updated_at, revoked_at \
         FROM permissions_grants \
         WHERE user_id = ? AND revoked_at IS NULL \
         ORDER BY created_at",
    )
    .bind(user_id.to_string())
    .fetch_all(pool)
    .await?;
    rows.iter().map(grant_from_row).collect()
}

pub(super) async fn get_grant(
    pool: &MySqlPool,
    id: Uuid,
) -> Result<Option<PermissionsGrant>, RepoError> {
    grant_by_id(pool, id).await
}

pub(super) async fn list_grants(
    pool: &MySqlPool,
    user_id: Option<Uuid>,
    database_id: Option<Uuid>,
    page: Page,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    // pg's `$1::uuid IS NULL OR …` collapse trick depends on pg's
    // ability to type-tag a NULL. Mysql's parameter typing happens at
    // bind time — a NULL bound parameter is fine — so `? IS NULL OR …`
    // works the same way, and the planner still uses the per-column
    // index when the filter is set.
    let rows = sqlx::query(
        "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                constraints_json, created_at, updated_at, revoked_at \
         FROM permissions_grants \
         WHERE revoked_at IS NULL \
           AND (? IS NULL OR user_id = ?) \
           AND (? IS NULL OR database_id = ?) \
         ORDER BY created_at, id \
         LIMIT ? OFFSET ?",
    )
    .bind(user_id.map(|u| u.to_string()))
    .bind(user_id.map(|u| u.to_string()))
    .bind(database_id.map(|d| d.to_string()))
    .bind(database_id.map(|d| d.to_string()))
    .bind(page.limit())
    .bind(page.offset())
    .fetch_all(pool)
    .await?;
    rows.iter().map(grant_from_row).collect()
}

#[cfg(any(test, feature = "test-support"))]
pub(super) async fn revoke_grant(pool: &MySqlPool, id: Uuid) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_grants SET revoked_at = NOW(6) \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Same one-round-trip join as the pg store: live user ⋈ live grants ⟕ live
/// databases; a specific grant on a soft-deleted database drops here.
pub(super) async fn live_grants_for_sub(
    pool: &MySqlPool,
    user_sub: &str,
) -> Result<Vec<LiveGrant>, RepoError> {
    let rows = sqlx::query(
        "SELECT g.id, COALESCE(g.server, d.server) AS server, d.db_name, g.action, \
                g.constraints_json \
         FROM permissions_grants g \
         JOIN permissions_users u ON u.id = g.user_id \
         LEFT JOIN permissions_databases d ON d.id = g.database_id AND d.deleted_at IS NULL \
         WHERE u.user_sub = ? AND u.deleted_at IS NULL AND g.revoked_at IS NULL \
           AND (g.db_name_wildcard OR d.id IS NOT NULL) \
         ORDER BY g.created_at, g.id",
    )
    .bind(user_sub)
    .fetch_all(pool)
    .await?;
    rows.iter().map(live_grant_from_row).collect()
}
