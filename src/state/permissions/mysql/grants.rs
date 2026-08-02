//! Grant CRUD operations for the MySQL permissions store.

use serde_json::Value as JsonValue;
use sqlx::MySqlPool;
use uuid::Uuid;

use super::super::{GrantAction, GrantTarget, Page, PermissionsGrant, RepoError};
use super::rows::grant_from_row;

pub(super) async fn create_grant(
    pool: &MySqlPool,
    user_id: Uuid,
    target: GrantTarget,
    action: GrantAction,
    constraints: JsonValue,
) -> Result<PermissionsGrant, RepoError> {
    let (server, database_id, wildcard) = match &target {
        GrantTarget::Specific { database_id } => (None, Some(*database_id), false),
        GrantTarget::Wildcard { server } => (Some(server.clone()), None, true),
    };
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

pub(super) async fn update_grant(
    pool: &MySqlPool,
    id: Uuid,
    action: Option<GrantAction>,
    constraints: Option<JsonValue>,
) -> Result<Option<PermissionsGrant>, RepoError> {
    // One transaction so the reread returns exactly the row this UPDATE wrote
    // (matches the atomic create path and the PATCH contract).
    let mut tx = pool.begin().await?;
    let res = sqlx::query(
        "UPDATE permissions_grants \
         SET action = COALESCE(?, action), \
             constraints_json = COALESCE(?, constraints_json), \
             updated_at = NOW(6) \
         WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(action.map(|a| a.as_db_str()))
    .bind(constraints)
    .bind(id.to_string())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(None);
    }
    let row = grant_by_id(&mut *tx, id).await?;
    tx.commit().await?;
    Ok(row)
}

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
