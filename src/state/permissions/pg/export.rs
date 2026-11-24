//! Admin-only reads beyond the [`super::super::PermissionsRepo`] surface:
//! the whole-store export, the batch-apply natural-key lookup, and a live
//! user by subject. The admin API is pg-only (boot rejects it on mysql), so
//! these are not on the trait.

use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::{
    GrantAction, GrantTarget, LiveGrant, PermissionsGrant, PermissionsUser, RepoError,
};
use super::rows::{
    GRANT_COLUMNS, USER_COLUMNS, grant_from_row, live_grant_from_row, user_from_row,
};

/// Every live grant of every live user, with its owner's `user_sub`, in the
/// resolver's own projection — same joins as `live_grants_for_sub`, so the
/// export shows exactly what evaluation would load.
pub async fn all_live_grants(pool: &PgPool) -> Result<Vec<(String, LiveGrant)>, RepoError> {
    let rows = sqlx::query(
        "SELECT u.user_sub, g.id, COALESCE(g.server, d.server) AS server, d.db_name, \
                g.action, g.constraints, g.expires_at \
         FROM permissions_grants g \
         JOIN permissions_users u ON u.id = g.user_id \
         LEFT JOIN permissions_databases d ON d.id = g.database_id AND d.deleted_at IS NULL \
         WHERE u.deleted_at IS NULL AND g.revoked_at IS NULL \
           AND (g.db_name_wildcard OR d.id IS NOT NULL) \
         ORDER BY u.user_sub, g.created_at, g.id",
    )
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| Ok((row.try_get("user_sub")?, live_grant_from_row(row)?)))
        .collect()
}

/// The live user `user_sub`, if any.
pub async fn live_user_by_sub(
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

/// Lock the oldest live grant of `user_id` on `target` for `action` — the
/// natural key a batch upsert updates in place instead of duplicating.
pub async fn tx_lock_grant_by_key(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    target: &GrantTarget,
    action: GrantAction,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let (server, database_id, wildcard) = target.columns();
    let sql = format!(
        "SELECT {GRANT_COLUMNS} FROM permissions_grants \
         WHERE user_id = $1 AND revoked_at IS NULL AND action = $2 \
           AND db_name_wildcard = $3 \
           AND server IS NOT DISTINCT FROM $4 AND database_id IS NOT DISTINCT FROM $5 \
         ORDER BY created_at, id LIMIT 1 FOR UPDATE"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(user_id)
        .bind(action.as_db_str())
        .bind(wildcard)
        .bind(server)
        .bind(database_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(grant_from_row).transpose()
}
