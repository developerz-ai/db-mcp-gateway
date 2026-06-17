//! Transactional SQL helpers for the admin grants handlers.
//!
//! Same rationale as [`super::super::users`] and [`super::super::databases`]:
//! the data write MUST share the tx with the audit log so an audit failure
//! rolls back both. The [`PermissionsRepo`] trait stays pool-backed (resolver
//! hot path doesn't need transactions); the admin handlers inline the SQL here.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::state::permissions::{GrantAction, GrantTarget, PermissionsGrant, RepoError};

pub(super) async fn tx_create_grant(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    target: GrantTarget,
    action: GrantAction,
    constraints: JsonValue,
) -> Result<PermissionsGrant, RepoError> {
    let (server, database_id, wildcard) = match &target {
        GrantTarget::Specific { database_id } => (None, Some(*database_id), false),
        GrantTarget::Wildcard { server } => (Some(server.clone()), None, true),
    };
    let row = sqlx::query(
        "INSERT INTO permissions_grants \
         (user_id, server, database_id, db_name_wildcard, action, constraints) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, user_id, server, database_id, db_name_wildcard, action, \
                   constraints, created_at, updated_at, revoked_at",
    )
    .bind(user_id)
    .bind(server)
    .bind(database_id)
    .bind(wildcard)
    .bind(action.as_db_str())
    .bind(&constraints)
    .fetch_one(&mut **tx)
    .await?;
    grant_from_row_admin(&row)
}

pub(super) async fn tx_get_grant_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                constraints, created_at, updated_at, revoked_at \
         FROM permissions_grants \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| grant_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_update_grant(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    action: Option<GrantAction>,
    constraints: Option<JsonValue>,
) -> Result<Option<PermissionsGrant>, RepoError> {
    let row = sqlx::query(
        "UPDATE permissions_grants \
         SET action = COALESCE($2, action), \
             constraints = COALESCE($3, constraints), \
             updated_at = now() \
         WHERE id = $1 AND revoked_at IS NULL \
         RETURNING id, user_id, server, database_id, db_name_wildcard, action, \
                   constraints, created_at, updated_at, revoked_at",
    )
    .bind(id)
    .bind(action.map(|a| a.as_db_str()))
    .bind(constraints)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| grant_from_row_admin(&r)).transpose()
}

pub(super) async fn tx_revoke_grant(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_grants SET revoked_at = now() \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Look up the `user_sub` for a given `permissions_users.id`. Used post-commit
/// by the cache invalidation hook — the cache is keyed by `user_sub` (JWT
/// subject) while grants reference users by row id. Reads through the tx so
/// it can see uncommitted user rows (not relevant in current flows, but
/// harmless and matches the consistency model).
pub(super) async fn tx_user_sub_for_id(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<Option<String>, RepoError> {
    let row = sqlx::query("SELECT user_sub FROM permissions_users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row
        .map(|r| r.try_get::<String, _>("user_sub"))
        .transpose()?)
}

fn grant_from_row_admin(row: &sqlx::postgres::PgRow) -> Result<PermissionsGrant, RepoError> {
    let action_str: String = row.try_get("action")?;
    let server: Option<String> = row.try_get("server")?;
    let database_id: Option<Uuid> = row.try_get("database_id")?;
    let wildcard: bool = row.try_get("db_name_wildcard")?;
    let target = match (server.clone(), database_id, wildcard) {
        (None, Some(db_id), false) => GrantTarget::Specific { database_id: db_id },
        (Some(srv), None, true) => GrantTarget::Wildcard { server: srv },
        _ => {
            return Err(RepoError::InvalidGrantTarget {
                server,
                database_id,
                wildcard,
            });
        }
    };
    Ok(PermissionsGrant {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        target,
        action: GrantAction::parse(&action_str)?,
        constraints: row.try_get("constraints")?,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        revoked_at: row.try_get::<Option<DateTime<Utc>>, _>("revoked_at")?,
    })
}
