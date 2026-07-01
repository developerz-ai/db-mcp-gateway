//! Database CRUD operations for the MySQL permissions store.

use sqlx::MySqlPool;
use uuid::Uuid;

use super::super::{DbType, PermissionsDatabase, RepoError};
use super::rows::database_from_row;

pub(super) async fn create_database(
    pool: &MySqlPool,
    server: &str,
    db_name: &str,
    db_type: DbType,
) -> Result<PermissionsDatabase, RepoError> {
    let new_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permissions_databases \
         (id, server, db_name, db_type, created_at, updated_at) \
         VALUES (?, ?, ?, ?, NOW(6), NOW(6))",
    )
    .bind(new_id.to_string())
    .bind(server)
    .bind(db_name)
    .bind(db_type.as_db_str())
    .execute(pool)
    .await?;
    get_database(pool, new_id)
        .await?
        .ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))
}

pub(super) async fn get_database(
    pool: &MySqlPool,
    id: Uuid,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let row = sqlx::query(
        "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
         FROM permissions_databases \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    row.map(|r| database_from_row(&r)).transpose()
}

pub(super) async fn list_databases(
    pool: &MySqlPool,
) -> Result<Vec<PermissionsDatabase>, RepoError> {
    let rows = sqlx::query(
        "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
         FROM permissions_databases \
         WHERE deleted_at IS NULL \
         ORDER BY server, db_name",
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(database_from_row).collect()
}

pub(super) async fn update_database(
    pool: &MySqlPool,
    id: Uuid,
    server: Option<&str>,
    db_name: Option<&str>,
    db_type: Option<DbType>,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_databases \
         SET server = COALESCE(?, server), \
             db_name = COALESCE(?, db_name), \
             db_type = COALESCE(?, db_type), \
             updated_at = NOW(6) \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(server)
    .bind(db_name)
    .bind(db_type.map(|t| t.as_db_str()))
    .bind(id.to_string())
    .execute(pool)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(None);
    }
    get_database(pool, id).await
}

pub(super) async fn soft_delete_database(pool: &MySqlPool, id: Uuid) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_databases SET deleted_at = NOW(6) \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}
