//! `permissions_grants` SQL: pool reads, the resolver's one-query loader, and
//! the transactional writes the admin API audits.

use serde_json::Value as JsonValue;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::super::{GrantAction, GrantTarget, LiveGrant, Page, PermissionsGrant, RepoError};
use super::rows::{GRANT_COLUMNS, grant_from_row, live_grant_from_row};

pub(super) async fn get_grant(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let sql = format!(
        "SELECT {GRANT_COLUMNS} FROM permissions_grants WHERE id = $1 AND revoked_at IS NULL"
    );
    let row = sqlx::query(&sql).bind(id).fetch_optional(pool).await?;
    row.as_ref().map(grant_from_row).transpose()
}

pub(super) async fn list_grants(
    pool: &PgPool,
    user_id: Option<Uuid>,
    database_id: Option<Uuid>,
    page: Page,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    // `$n IS NULL OR …` keeps one static statement for every filter combination.
    let sql = format!(
        "SELECT {GRANT_COLUMNS} FROM permissions_grants \
         WHERE revoked_at IS NULL \
           AND ($1::uuid IS NULL OR user_id = $1) \
           AND ($2::uuid IS NULL OR database_id = $2) \
         ORDER BY created_at, id LIMIT $3 OFFSET $4"
    );
    let rows = sqlx::query(&sql)
        .bind(user_id)
        .bind(database_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(pool)
        .await?;
    rows.iter().map(grant_from_row).collect()
}

/// One round trip: live user ⋈ live grants ⟕ live databases. A specific grant
/// whose database is soft-deleted drops here, so a re-registered
/// `(server, db_name)` never inherits it.
pub(super) async fn live_grants_for_sub(
    pool: &PgPool,
    user_sub: &str,
) -> Result<Vec<LiveGrant>, RepoError> {
    let rows = sqlx::query(
        "SELECT g.id, COALESCE(g.server, d.server) AS server, d.db_name, g.action, \
                g.constraints \
         FROM permissions_grants g \
         JOIN permissions_users u ON u.id = g.user_id \
         LEFT JOIN permissions_databases d ON d.id = g.database_id AND d.deleted_at IS NULL \
         WHERE u.user_sub = $1 AND u.deleted_at IS NULL AND g.revoked_at IS NULL \
           AND (g.db_name_wildcard OR d.id IS NOT NULL) \
         ORDER BY g.created_at, g.id",
    )
    .bind(user_sub)
    .fetch_all(pool)
    .await?;
    rows.iter().map(live_grant_from_row).collect()
}

/// Insert a grant iff its user — and, for a specific grant, its database — is
/// live. `FOR SHARE` holds both rows until commit, so a concurrent soft-delete
/// (and its grant cascade) orders strictly before or after this insert.
/// Returns `None` when a referenced row is missing or soft-deleted.
pub async fn tx_create_grant(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    target: &GrantTarget,
    action: GrantAction,
    constraints: &JsonValue,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let (server, database_id, wildcard) = target.columns();
    let sql = format!(
        "WITH u AS (SELECT id FROM permissions_users \
                    WHERE id = $1 AND deleted_at IS NULL FOR SHARE), \
              d AS (SELECT id FROM permissions_databases \
                    WHERE id = $3 AND deleted_at IS NULL FOR SHARE) \
         INSERT INTO permissions_grants \
             (user_id, server, database_id, db_name_wildcard, action, constraints) \
         SELECT u.id, $2, $3, $4, $5, $6 FROM u \
         WHERE $3::uuid IS NULL OR EXISTS (SELECT 1 FROM d) \
         RETURNING {GRANT_COLUMNS}"
    );
    let row = sqlx::query(&sql)
        .bind(user_id)
        .bind(server)
        .bind(database_id)
        .bind(wildcard)
        .bind(action.as_db_str())
        .bind(constraints)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(grant_from_row).transpose()
}

/// Lock the live grant `id` for the rest of the transaction.
pub async fn tx_lock_grant(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let sql = format!(
        "SELECT {GRANT_COLUMNS} FROM permissions_grants \
         WHERE id = $1 AND revoked_at IS NULL FOR UPDATE"
    );
    let row = sqlx::query(&sql).bind(id).fetch_optional(&mut **tx).await?;
    row.as_ref().map(grant_from_row).transpose()
}

/// Set `action` (when given) and replace `constraints` with the already
/// merged object. Returns `None` when the grant is missing or revoked.
pub async fn tx_update_grant(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    action: Option<GrantAction>,
    constraints: &JsonValue,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let sql = format!(
        "UPDATE permissions_grants \
         SET action = COALESCE($2, action), constraints = $3, updated_at = now() \
         WHERE id = $1 AND revoked_at IS NULL RETURNING {GRANT_COLUMNS}"
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(action.map(GrantAction::as_db_str))
        .bind(constraints)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(grant_from_row).transpose()
}

pub async fn tx_revoke_grant(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Revoke every live grant of `user_id`; returns them as they were before the
/// revoke (only `revoked_at` changes) for one audit row each.
pub async fn tx_revoke_grants_for_user(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    revoke_where(tx, "user_id", user_id).await
}

/// Revoke every live specific grant on `database_id`. Wildcards name a
/// server, not a database row, and are untouched.
pub async fn tx_revoke_grants_for_database(
    tx: &mut Transaction<'_, Postgres>,
    database_id: Uuid,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    revoke_where(tx, "database_id", database_id).await
}

async fn revoke_where(
    tx: &mut Transaction<'_, Postgres>,
    column: &'static str,
    id: Uuid,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    let sql = format!(
        "UPDATE permissions_grants SET revoked_at = now() \
         WHERE {column} = $1 AND revoked_at IS NULL RETURNING {GRANT_COLUMNS}"
    );
    let rows = sqlx::query(&sql).bind(id).fetch_all(&mut **tx).await?;
    let mut grants = rows
        .iter()
        .map(grant_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    // Audit rows in a stable order, independent of the update's scan order.
    grants.sort_by_key(|g| (g.created_at, g.id));
    for g in &mut grants {
        g.revoked_at = None;
    }
    Ok(grants)
}

#[cfg(any(test, feature = "test-support"))]
pub(super) async fn list_grants_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<PermissionsGrant>, RepoError> {
    let sql = format!(
        "SELECT {GRANT_COLUMNS} FROM permissions_grants \
         WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at"
    );
    let rows = sqlx::query(&sql).bind(user_id).fetch_all(pool).await?;
    rows.iter().map(grant_from_row).collect()
}
