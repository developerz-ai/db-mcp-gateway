//! Postgres impl of [`PermissionsRepo`]. Uses the shared state pool — same
//! pool the audit writer and session denylist use. No new connection.
//!
//! Style mirrors `audit::log`: plain `sqlx::query` with positional binds, no
//! `query!` macros (those would force a `DATABASE_URL` at compile time, which
//! we deliberately avoid — the repo's a fresh dev DB, no offline metadata).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{PgPool, Row, postgres::PgRow};
use uuid::Uuid;

use super::{
    DbType, GrantAction, GrantTarget, PermissionsDatabase, PermissionsGrant, PermissionsRepo,
    PermissionsUser, RepoError,
};

#[derive(Debug, Clone)]
pub struct PgPermissionsRepo {
    pool: PgPool,
}

impl PgPermissionsRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionsRepo for PgPermissionsRepo {
    async fn upsert_user(
        &self,
        user_sub: &str,
        user_email: &str,
        groups: &[String],
    ) -> Result<PermissionsUser, RepoError> {
        // ON CONFLICT only fires on a live row (the unique index is partial
        // on deleted_at IS NULL). A soft-deleted user with the same sub
        // therefore inserts a new row — which is what we want: the old row is
        // the audit trail of the prior membership, the new row is today's.
        // Restoring a still-live soft-delete is not a flow we expose.
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
        .fetch_one(&self.pool)
        .await?;
        Ok(user_from_row(&row)?)
    }

    async fn get_user_by_sub(&self, user_sub: &str) -> Result<Option<PermissionsUser>, RepoError> {
        let row = sqlx::query(
            "SELECT id, user_sub, user_email, groups, created_at, updated_at, deleted_at \
             FROM permissions_users \
             WHERE user_sub = $1 AND deleted_at IS NULL",
        )
        .bind(user_sub)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| user_from_row(&r)).transpose()
    }

    async fn list_users(&self) -> Result<Vec<PermissionsUser>, RepoError> {
        let rows = sqlx::query(
            "SELECT id, user_sub, user_email, groups, created_at, updated_at, deleted_at \
             FROM permissions_users \
             WHERE deleted_at IS NULL \
             ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(user_from_row).collect()
    }

    async fn soft_delete_user(&self, id: Uuid) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "UPDATE permissions_users SET deleted_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn create_database(
        &self,
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
        .fetch_one(&self.pool)
        .await?;
        database_from_row(&row)
    }

    async fn get_database(&self, id: Uuid) -> Result<Option<PermissionsDatabase>, RepoError> {
        let row = sqlx::query(
            "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
             FROM permissions_databases \
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| database_from_row(&r)).transpose()
    }

    async fn list_databases(&self) -> Result<Vec<PermissionsDatabase>, RepoError> {
        let rows = sqlx::query(
            "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
             FROM permissions_databases \
             WHERE deleted_at IS NULL \
             ORDER BY server, db_name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(database_from_row).collect()
    }

    async fn soft_delete_database(&self, id: Uuid) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "UPDATE permissions_databases SET deleted_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn create_grant(
        &self,
        user_id: Uuid,
        target: GrantTarget,
        action: GrantAction,
        constraints: JsonValue,
    ) -> Result<PermissionsGrant, RepoError> {
        // Encode the XOR branches: Specific uses database_id (server NULL,
        // wildcard false); Wildcard uses server (database_id NULL, wildcard
        // true). The DB CHECK is the safety net — this is the contract.
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
        .fetch_one(&self.pool)
        .await?;
        grant_from_row(&row)
    }

    async fn list_grants_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        let rows = sqlx::query(
            "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                    constraints, created_at, updated_at, revoked_at \
             FROM permissions_grants \
             WHERE user_id = $1 AND revoked_at IS NULL \
             ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(grant_from_row).collect()
    }

    async fn revoke_grant(&self, id: Uuid) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "UPDATE permissions_grants SET revoked_at = now() \
             WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

fn user_from_row(row: &PgRow) -> Result<PermissionsUser, RepoError> {
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

fn database_from_row(row: &PgRow) -> Result<PermissionsDatabase, RepoError> {
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

fn grant_from_row(row: &PgRow) -> Result<PermissionsGrant, RepoError> {
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
