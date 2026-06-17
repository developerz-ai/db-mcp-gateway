//! Transactional SQL helpers for the admin databases handlers.
//!
//! Same rationale as [`super::super::users`]: the data write MUST share the
//! tx with the audit log so an audit failure rolls back both. The
//! [`PermissionsRepo`] trait stays pool-backed (resolver hot path doesn't
//! need transactions); the admin handlers inline the SQL here.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::state::permissions::{DbType, PermissionsDatabase, RepoError};

pub(super) async fn tx_create_database(
    tx: &mut Transaction<'_, Postgres>,
    server: &str,
    db_name: &str,
    db_type: DbType,
) -> Result<PermissionsDatabase, RepoError> {
    let row = sqlx::query(
        "INSERT INTO permissions_databases (server, db_name, db_type) \
         VALUES ($1, $2, $3) \
         RETURNING id, server, db_name, db_type, created_at, updated_at, deleted_at",
    )
    .bind(server)
    .bind(db_name)
    .bind(db_type.as_db_str())
    .fetch_one(&mut **tx)
    .await?;
    database_from_row_admin(&row)
}

pub(super) async fn tx_get_database_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let row = sqlx::query(
        "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
         FROM permissions_databases \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| database_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_update_database(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: Option<&str>,
    db_name: Option<&str>,
    db_type: Option<DbType>,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let row = sqlx::query(
        "UPDATE permissions_databases \
         SET server = COALESCE($2, server), \
             db_name = COALESCE($3, db_name), \
             db_type = COALESCE($4, db_type), \
             updated_at = now() \
         WHERE id = $1 AND deleted_at IS NULL \
         RETURNING id, server, db_name, db_type, created_at, updated_at, deleted_at",
    )
    .bind(id)
    .bind(server)
    .bind(db_name)
    .bind(db_type.map(|t| t.as_db_str()))
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| database_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_soft_delete_database(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_databases SET deleted_at = now() \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

fn database_from_row_admin(row: &sqlx::postgres::PgRow) -> Result<PermissionsDatabase, RepoError> {
    let db_type_str: String = row.try_get("db_type")?;
    Ok(PermissionsDatabase {
        id: row.try_get("id")?,
        server: row.try_get("server")?,
        db_name: row.try_get("db_name")?,
        db_type: DbType::parse(&db_type_str)?,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        deleted_at: row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?,
    })
}
