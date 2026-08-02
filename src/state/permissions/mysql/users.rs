//! User CRUD operations for the MySQL permissions store.

use sqlx::MySqlPool;
use uuid::Uuid;

use super::super::{Page, PermissionsUser, RepoError};
use super::rows::user_from_row;

pub(super) async fn upsert_user(
    pool: &MySqlPool,
    user_sub: &str,
    user_email: &str,
    groups: &[String],
) -> Result<PermissionsUser, RepoError> {
    let groups_json = serde_json::to_value(groups).map_err(RepoError::EncodeGroups)?;
    // The unique index is on `live_user_sub` — NULL on soft-deleted
    // rows, equal to `user_sub` on live ones. So `ON DUPLICATE KEY`
    // only fires when a *live* row with the same sub already exists,
    // matching pg's partial-index semantics.
    let new_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permissions_users \
         (id, user_sub, user_email, groups_json, created_at, updated_at) \
         VALUES (?, ?, ?, ?, NOW(6), NOW(6)) \
         ON DUPLICATE KEY UPDATE \
             user_email = VALUES(user_email), \
             groups_json = VALUES(groups_json), \
             updated_at = NOW(6)",
    )
    .bind(new_id.to_string())
    .bind(user_sub)
    .bind(user_email)
    .bind(&groups_json)
    .execute(pool)
    .await?;
    // SELECT by `user_sub` (not `new_id`) — the upsert may have hit the
    // existing row instead of inserting `new_id`. The partial-uniqueness
    // means there's at most one live row per `user_sub` to return.
    get_user_by_sub(pool, user_sub)
        .await?
        .ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))
}

pub(super) async fn get_user_by_sub(
    pool: &MySqlPool,
    user_sub: &str,
) -> Result<Option<PermissionsUser>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE user_sub = ? AND deleted_at IS NULL",
    )
    .bind(user_sub)
    .fetch_optional(pool)
    .await?;
    row.map(|r| user_from_row(&r)).transpose()
}

pub(super) async fn get_user(
    pool: &MySqlPool,
    id: Uuid,
) -> Result<Option<PermissionsUser>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?;
    row.map(|r| user_from_row(&r)).transpose()
}

pub(super) async fn update_user(
    pool: &MySqlPool,
    id: Uuid,
    user_email: Option<&str>,
    groups: Option<&[String]>,
) -> Result<Option<PermissionsUser>, RepoError> {
    let groups_json = match groups {
        Some(g) => Some(serde_json::to_value(g).map_err(RepoError::EncodeGroups)?),
        None => None,
    };
    // One transaction so the reread returns exactly the row this UPDATE wrote —
    // a concurrent login sync or delete can't slip in between (PATCH contract in
    // `PermissionsRepo::update_user`).
    let mut tx = pool.begin().await?;
    let res = sqlx::query(
        "UPDATE permissions_users \
         SET user_email = COALESCE(?, user_email), \
             groups_json = COALESCE(?, groups_json), \
             updated_at = NOW(6) \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(user_email)
    .bind(groups_json)
    .bind(id.to_string())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(None);
    }
    // Re-read so callers (admin API audit) see the post-update row.
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(id.to_string())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    row.map(|r| user_from_row(&r)).transpose()
}

pub(super) async fn list_users(
    pool: &MySqlPool,
    page: Page,
) -> Result<Vec<PermissionsUser>, RepoError> {
    let rows = sqlx::query(
        // `created_at, id` — created_at alone is not unique, and a
        // non-deterministic tiebreak lets a row repeat or vanish across pages.
        "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE deleted_at IS NULL \
         ORDER BY created_at, id \
         LIMIT ? OFFSET ?",
    )
    .bind(page.limit())
    .bind(page.offset())
    .fetch_all(pool)
    .await?;
    rows.iter().map(user_from_row).collect()
}

pub(super) async fn soft_delete_user(pool: &MySqlPool, id: Uuid) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_users SET deleted_at = NOW(6) \
         WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}
