//! `permissions_databases` SQL: pool reads plus the transactional writes the
//! admin API audits.

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::super::{DbType, Page, PermissionsDatabase, RepoError};
use super::rows::{DATABASE_COLUMNS, database_from_row};

pub(super) async fn get_database(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let sql = format!(
        "SELECT {DATABASE_COLUMNS} FROM permissions_databases \
         WHERE id = $1 AND deleted_at IS NULL"
    );
    let row = sqlx::query(&sql).bind(id).fetch_optional(pool).await?;
    row.as_ref().map(database_from_row).transpose()
}

pub(super) async fn list_databases(
    pool: &PgPool,
    page: Page,
) -> Result<Vec<PermissionsDatabase>, RepoError> {
    // `(server, db_name)` is unique among live rows: already a total order.
    let sql = format!(
        "SELECT {DATABASE_COLUMNS} FROM permissions_databases WHERE deleted_at IS NULL \
         ORDER BY server, db_name LIMIT $1 OFFSET $2"
    );
    let rows = sqlx::query(&sql)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(pool)
        .await?;
    rows.iter().map(database_from_row).collect()
}

pub async fn tx_create_database(
    tx: &mut Transaction<'_, Postgres>,
    server: &str,
    db_name: &str,
    db_type: DbType,
) -> Result<PermissionsDatabase, RepoError> {
    let sql = format!(
        "INSERT INTO permissions_databases (server, db_name, db_type) VALUES ($1, $2, $3) \
         RETURNING {DATABASE_COLUMNS}"
    );
    let row = sqlx::query(&sql)
        .bind(server)
        .bind(db_name)
        .bind(db_type.as_db_str())
        .fetch_one(&mut **tx)
        .await?;
    database_from_row(&row)
}

/// Lock the live database `id` for the rest of the transaction.
pub async fn tx_lock_database(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let sql = format!(
        "SELECT {DATABASE_COLUMNS} FROM permissions_databases \
         WHERE id = $1 AND deleted_at IS NULL FOR UPDATE"
    );
    let row = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await?;
    row.as_ref().map(database_from_row).transpose()
}

/// Partial update; `None` leaves the column. Returns `None` when the database
/// is missing or soft-deleted.
pub async fn tx_update_database(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: Option<&str>,
    db_name: Option<&str>,
    db_type: Option<DbType>,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let sql = format!(
        "UPDATE permissions_databases \
         SET server = COALESCE($2, server), db_name = COALESCE($3, db_name), \
             db_type = COALESCE($4, db_type), updated_at = now() \
         WHERE id = $1 AND deleted_at IS NULL RETURNING {DATABASE_COLUMNS}"
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(server)
        .bind(db_name)
        .bind(db_type.map(DbType::as_db_str))
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(database_from_row).transpose()
}

pub async fn tx_soft_delete_database(
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
