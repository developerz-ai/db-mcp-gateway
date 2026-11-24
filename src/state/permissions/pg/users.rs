//! `permissions_users` SQL: pool reads plus the transactional writes the
//! admin API audits.

use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::{Page, PermissionsUser, RepoError};
use super::rows::{USER_COLUMNS, user_from_row};

pub(super) async fn get_user(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<PermissionsUser>, RepoError> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM permissions_users WHERE id = $1 AND deleted_at IS NULL"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.as_ref().map(user_from_row).transpose()
}

pub(super) async fn list_users(
    pool: &PgPool,
    page: Page,
) -> Result<Vec<PermissionsUser>, RepoError> {
    // `created_at, id`: created_at alone is not unique, and a
    // non-deterministic tiebreak lets a row repeat or vanish across pages.
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM permissions_users WHERE deleted_at IS NULL \
         ORDER BY created_at, id LIMIT $1 OFFSET $2"
    );
    let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(pool)
        .await?;
    rows.iter().map(user_from_row).collect()
}

/// Lock the acting admin's live row, inserting it from the session snapshot
/// only if absent, and return its id for `permissions_audit`. An existing row
/// is never rewritten: refreshing its email or groups here would be an
/// unaudited write that breaks the row's before/after chain and bumps
/// `updated_at` under another admin's `expected_updated_at`. Admin mutations
/// call this FIRST in their transaction so every admin write takes its
/// user-row lock before any target lock — one fixed lock order.
///
/// A concurrent soft-delete of the actor's row between the insert and the
/// lock leaves no live row: `RowNotFound`, and the caller fails the write.
pub async fn tx_lock_actor(
    tx: &mut Transaction<'_, Postgres>,
    sub: &str,
    email: &str,
    groups: &[String],
) -> Result<Uuid, RepoError> {
    let groups_json = serde_json::to_value(groups).map_err(RepoError::EncodeGroups)?;
    sqlx::query(
        "INSERT INTO permissions_users (user_sub, user_email, groups) VALUES ($1, $2, $3) \
         ON CONFLICT (user_sub) WHERE deleted_at IS NULL DO NOTHING",
    )
    .bind(sub)
    .bind(email)
    .bind(&groups_json)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "SELECT id FROM permissions_users WHERE user_sub = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(sub)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    Ok(row.try_get("id")?)
}

/// `user_sub` of a user row, live or soft-deleted. Unlocked: `user_sub` is
/// immutable, so callers use it to pick a lock order before locking.
pub async fn tx_user_sub(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<String>, RepoError> {
    let row = sqlx::query("SELECT user_sub FROM permissions_users WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(|r| r.try_get("user_sub")).transpose()?)
}

/// Lock the live user `user_sub` for the rest of the transaction.
///
/// The transaction-scoped advisory lock serialises two creates of a
/// not-yet-existing subject too — a row lock cannot, there being no row —
/// so each create's `before` snapshot is the previous create's `after`.
pub async fn tx_lock_user_by_sub(
    tx: &mut Transaction<'_, Postgres>,
    user_sub: &str,
) -> Result<Option<PermissionsUser>, RepoError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('permissions_users:' || $1, 0))")
        .bind(user_sub)
        .execute(&mut **tx)
        .await?;
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM permissions_users \
         WHERE user_sub = $1 AND deleted_at IS NULL FOR UPDATE"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(user_sub)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(user_from_row).transpose()
}

/// Lock the live user `id` for the rest of the transaction.
pub async fn tx_lock_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsUser>, RepoError> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM permissions_users \
         WHERE id = $1 AND deleted_at IS NULL FOR UPDATE"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(user_from_row).transpose()
}

/// Insert or refresh the live row for `user_sub`. The unique index is partial
/// on `deleted_at IS NULL`, so a soft-deleted prior row stays as history and
/// a fresh row is inserted beside it.
pub async fn tx_upsert_user(
    tx: &mut Transaction<'_, Postgres>,
    user_sub: &str,
    user_email: &str,
    groups: &[String],
) -> Result<PermissionsUser, RepoError> {
    let groups_json = serde_json::to_value(groups).map_err(RepoError::EncodeGroups)?;
    let sql = format!(
        "INSERT INTO permissions_users (user_sub, user_email, groups) VALUES ($1, $2, $3) \
         ON CONFLICT (user_sub) WHERE deleted_at IS NULL \
         DO UPDATE SET user_email = EXCLUDED.user_email, groups = EXCLUDED.groups, \
                       updated_at = now() \
         RETURNING {USER_COLUMNS}"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(user_sub)
        .bind(user_email)
        .bind(&groups_json)
        .fetch_one(&mut **tx)
        .await?;
    user_from_row(&row)
}

/// Partial update; `None` leaves the column. Returns `None` when the user is
/// missing or soft-deleted.
pub async fn tx_update_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_email: Option<&str>,
    groups: Option<&[String]>,
) -> Result<Option<PermissionsUser>, RepoError> {
    let groups_json = groups
        .map(serde_json::to_value)
        .transpose()
        .map_err(RepoError::EncodeGroups)?;
    let sql = format!(
        "UPDATE permissions_users \
         SET user_email = COALESCE($2, user_email), groups = COALESCE($3, groups), \
             updated_at = now() \
         WHERE id = $1 AND deleted_at IS NULL RETURNING {USER_COLUMNS}"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .bind(user_email)
        .bind(groups_json)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(user_from_row).transpose()
}

pub async fn tx_soft_delete_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

#[cfg(any(test, feature = "test-support"))]
pub(super) async fn get_user_by_sub(
    pool: &PgPool,
    user_sub: &str,
) -> Result<Option<PermissionsUser>, RepoError> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM permissions_users WHERE user_sub = $1 AND deleted_at IS NULL"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(user_sub)
        .fetch_optional(pool)
        .await?;
    row.as_ref().map(user_from_row).transpose()
}
