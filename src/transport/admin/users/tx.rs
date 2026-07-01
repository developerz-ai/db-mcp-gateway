use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::state::permissions::{PermissionsUser, RepoError};

pub(super) async fn tx_get_user_by_sub(
    tx: &mut Transaction<'_, Postgres>,
    user_sub: &str,
) -> Result<Option<PermissionsUser>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE user_sub = $1 AND deleted_at IS NULL",
    )
    .bind(user_sub)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| user_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_get_user_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsUser>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| user_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_upsert_user(
    tx: &mut Transaction<'_, Postgres>,
    user_sub: &str,
    user_email: &str,
    groups: &[String],
) -> Result<PermissionsUser, RepoError> {
    let groups_json = serde_json::to_value(groups).map_err(RepoError::EncodeGroups)?;
    let row = sqlx::query(
        "INSERT INTO permissions_users (user_sub, user_email, groups) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (user_sub) WHERE deleted_at IS NULL \
         DO UPDATE SET user_email = EXCLUDED.user_email, \
                       groups = EXCLUDED.groups, \
                       updated_at = now() \
         RETURNING id, user_sub, user_email, groups, created_at, updated_at, deleted_at",
    )
    .bind(user_sub)
    .bind(user_email)
    .bind(&groups_json)
    .fetch_one(&mut **tx)
    .await?;
    user_from_row_admin(&row)
}

pub(super) async fn tx_update_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_email: Option<&str>,
    groups: Option<&[String]>,
) -> Result<Option<PermissionsUser>, RepoError> {
    let groups_json = match groups {
        Some(g) => Some(serde_json::to_value(g).map_err(RepoError::EncodeGroups)?),
        None => None,
    };
    let row = sqlx::query(
        "UPDATE permissions_users \
         SET user_email = COALESCE($2, user_email), \
             groups = COALESCE($3, groups), \
             updated_at = now() \
         WHERE id = $1 AND deleted_at IS NULL \
         RETURNING id, user_sub, user_email, groups, created_at, updated_at, deleted_at",
    )
    .bind(id)
    .bind(user_email)
    .bind(groups_json)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| user_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_soft_delete_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_users SET deleted_at = now() \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub(super) fn user_from_row_admin(
    row: &sqlx::postgres::PgRow,
) -> Result<PermissionsUser, RepoError> {
    let groups_json: JsonValue = row.try_get("groups")?;
    let groups: Vec<String> =
        serde_json::from_value(groups_json).map_err(RepoError::DecodeGroups)?;
    Ok(PermissionsUser {
        id: row.try_get("id")?,
        user_sub: row.try_get("user_sub")?,
        user_email: row.try_get("user_email")?,
        groups,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        deleted_at: row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?,
    })
}
