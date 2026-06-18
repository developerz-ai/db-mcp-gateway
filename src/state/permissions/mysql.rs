//! MySQL impl of [`PermissionsRepo`] (#59). Mirrors [`super::pg`] 1:1
//! semantically; differences are mechanical SQL-dialect translations:
//!
//! - `$1`, `$2`, … → `?` (mysql placeholders are positional anonymous)
//! - `INSERT … RETURNING` (pg) → `INSERT` + post-INSERT `SELECT` (mysql
//!   has no `RETURNING`). The `id` is minted Rust-side (`Uuid::new_v4`)
//!   on every create so the follow-up `SELECT WHERE id = ?` is
//!   deterministic without `LAST_INSERT_ID()`.
//! - `INSERT … ON CONFLICT … DO UPDATE … RETURNING` (pg upsert) →
//!   `INSERT … ON DUPLICATE KEY UPDATE …` + `SELECT WHERE user_sub = ?`.
//! - Partial unique indexes (`WHERE deleted_at IS NULL`) emulated via
//!   generated columns (`live_user_sub`, etc.) the migration declares.
//!   NULL in a UNIQUE column doesn't conflict in mysql, so soft-deleted
//!   rows coexist with their replacements.
//! - JSON columns renamed `groups → groups_json`,
//!   `constraints → constraints_json` because `groups` and `constraints`
//!   are reserved in mysql 8 strict mode. The Rust struct shape is
//!   identical; the rename is purely SQL-side.
//!
//! Scope: this impl supports the **resolver hot path** end-to-end (#59
//! issue acceptance). The admin API (#52–#54) is intentionally
//! pg-only — boot fails fast when `permissions.store.driver = mysql`
//! AND `admin.enabled = true`. Spec 12 §"Storage backends": admin tx
//! helpers in `src/transport/admin/` use raw pg transactions with
//! `RETURNING`; porting them to a transactional trait is a separate
//! issue.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{MySqlPool, Row, mysql::MySqlRow};
use uuid::Uuid;

use super::{
    DbType, GrantAction, GrantTarget, PermissionsDatabase, PermissionsGrant, PermissionsRepo,
    PermissionsUser, RepoError,
};

#[derive(Debug, Clone)]
pub struct MysqlPermissionsRepo {
    pool: MySqlPool,
}

impl MysqlPermissionsRepo {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionsRepo for MysqlPermissionsRepo {
    async fn upsert_user(
        &self,
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
        .execute(&self.pool)
        .await?;
        // SELECT by `user_sub` (not `new_id`) — the upsert may have hit the
        // existing row instead of inserting `new_id`. The partial-uniqueness
        // means there's at most one live row per `user_sub` to return.
        self.get_user_by_sub(user_sub)
            .await?
            .ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))
    }

    async fn get_user_by_sub(&self, user_sub: &str) -> Result<Option<PermissionsUser>, RepoError> {
        let row = sqlx::query(
            "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
             FROM permissions_users \
             WHERE user_sub = ? AND deleted_at IS NULL",
        )
        .bind(user_sub)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| user_from_row(&r)).transpose()
    }

    async fn get_user(&self, id: Uuid) -> Result<Option<PermissionsUser>, RepoError> {
        let row = sqlx::query(
            "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
             FROM permissions_users \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| user_from_row(&r)).transpose()
    }

    async fn update_user(
        &self,
        id: Uuid,
        user_email: Option<&str>,
        groups: Option<&[String]>,
    ) -> Result<Option<PermissionsUser>, RepoError> {
        let groups_json = match groups {
            Some(g) => Some(serde_json::to_value(g).map_err(RepoError::EncodeGroups)?),
            None => None,
        };
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
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Ok(None);
        }
        // Re-read so callers (admin API audit) see the post-update row.
        self.get_user(id).await
    }

    async fn list_users(&self) -> Result<Vec<PermissionsUser>, RepoError> {
        let rows = sqlx::query(
            "SELECT id, user_sub, user_email, groups_json, created_at, updated_at, deleted_at \
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
            "UPDATE permissions_users SET deleted_at = NOW(6) \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id.to_string())
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
        .execute(&self.pool)
        .await?;
        self.get_database(new_id)
            .await?
            .ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))
    }

    async fn get_database(&self, id: Uuid) -> Result<Option<PermissionsDatabase>, RepoError> {
        let row = sqlx::query(
            "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
             FROM permissions_databases \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id.to_string())
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

    async fn update_database(
        &self,
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
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Ok(None);
        }
        self.get_database(id).await
    }

    async fn soft_delete_database(&self, id: Uuid) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "UPDATE permissions_databases SET deleted_at = NOW(6) \
             WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(id.to_string())
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
        let (server, database_id, wildcard) = match &target {
            GrantTarget::Specific { database_id } => (None, Some(*database_id), false),
            GrantTarget::Wildcard { server } => (Some(server.clone()), None, true),
        };
        let new_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO permissions_grants \
             (id, user_id, server, database_id, db_name_wildcard, action, constraints_json, \
              created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW(6), NOW(6))",
        )
        .bind(new_id.to_string())
        .bind(user_id.to_string())
        .bind(server)
        .bind(database_id.map(|id| id.to_string()))
        .bind(wildcard)
        .bind(action.as_db_str())
        .bind(&constraints)
        .execute(&self.pool)
        .await?;
        self.get_grant(new_id)
            .await?
            .ok_or(RepoError::Sqlx(sqlx::Error::RowNotFound))
    }

    async fn list_grants_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        let rows = sqlx::query(
            "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                    constraints_json, created_at, updated_at, revoked_at \
             FROM permissions_grants \
             WHERE user_id = ? AND revoked_at IS NULL \
             ORDER BY created_at",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(grant_from_row).collect()
    }

    async fn get_grant(&self, id: Uuid) -> Result<Option<PermissionsGrant>, RepoError> {
        let row = sqlx::query(
            "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                    constraints_json, created_at, updated_at, revoked_at \
             FROM permissions_grants \
             WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| grant_from_row(&r)).transpose()
    }

    async fn list_grants(
        &self,
        user_id: Option<Uuid>,
        database_id: Option<Uuid>,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        // pg's `$1::uuid IS NULL OR …` collapse trick depends on pg's
        // ability to type-tag a NULL. Mysql's parameter typing happens at
        // bind time — a NULL bound parameter is fine — so `? IS NULL OR …`
        // works the same way, and the planner still uses the per-column
        // index when the filter is set.
        let rows = sqlx::query(
            "SELECT id, user_id, server, database_id, db_name_wildcard, action, \
                    constraints_json, created_at, updated_at, revoked_at \
             FROM permissions_grants \
             WHERE revoked_at IS NULL \
               AND (? IS NULL OR user_id = ?) \
               AND (? IS NULL OR database_id = ?) \
             ORDER BY created_at",
        )
        .bind(user_id.map(|u| u.to_string()))
        .bind(user_id.map(|u| u.to_string()))
        .bind(database_id.map(|d| d.to_string()))
        .bind(database_id.map(|d| d.to_string()))
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(grant_from_row).collect()
    }

    async fn update_grant(
        &self,
        id: Uuid,
        action: Option<GrantAction>,
        constraints: Option<JsonValue>,
    ) -> Result<Option<PermissionsGrant>, RepoError> {
        let res = sqlx::query(
            "UPDATE permissions_grants \
             SET action = COALESCE(?, action), \
                 constraints_json = COALESCE(?, constraints_json), \
                 updated_at = NOW(6) \
             WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(action.map(|a| a.as_db_str()))
        .bind(constraints)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Ok(None);
        }
        self.get_grant(id).await
    }

    async fn revoke_grant(&self, id: Uuid) -> Result<bool, RepoError> {
        let res = sqlx::query(
            "UPDATE permissions_grants SET revoked_at = NOW(6) \
             WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }
}

/// Decode a CHAR(36) UUID column. The pg impl reads `UUID` natively;
/// mysql stores them as strings (no native UUID type until 8.0.13+),
/// so we parse on the way out.
fn parse_uuid(row: &MySqlRow, column: &str) -> Result<Uuid, RepoError> {
    let s: String = row.try_get(column)?;
    Uuid::parse_str(&s).map_err(|_| {
        RepoError::Sqlx(sqlx::Error::Decode(
            format!("invalid uuid in column `{column}`").into(),
        ))
    })
}

fn parse_optional_uuid(row: &MySqlRow, column: &str) -> Result<Option<Uuid>, RepoError> {
    let s: Option<String> = row.try_get(column)?;
    match s {
        None => Ok(None),
        Some(v) => Uuid::parse_str(&v).map(Some).map_err(|_| {
            RepoError::Sqlx(sqlx::Error::Decode(
                format!("invalid uuid in column `{column}`").into(),
            ))
        }),
    }
}

fn user_from_row(row: &MySqlRow) -> Result<PermissionsUser, RepoError> {
    let groups_json: JsonValue = row.try_get("groups_json")?;
    let groups: Vec<String> =
        serde_json::from_value(groups_json).map_err(RepoError::DecodeGroups)?;
    Ok(PermissionsUser {
        id: parse_uuid(row, "id")?,
        user_sub: row.try_get("user_sub")?,
        user_email: row.try_get("user_email")?,
        groups,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        deleted_at: row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?,
    })
}

fn database_from_row(row: &MySqlRow) -> Result<PermissionsDatabase, RepoError> {
    let db_type_str: String = row.try_get("db_type")?;
    Ok(PermissionsDatabase {
        id: parse_uuid(row, "id")?,
        server: row.try_get("server")?,
        db_name: row.try_get("db_name")?,
        db_type: DbType::parse(&db_type_str)?,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        deleted_at: row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?,
    })
}

fn grant_from_row(row: &MySqlRow) -> Result<PermissionsGrant, RepoError> {
    let action_str: String = row.try_get("action")?;
    let server: Option<String> = row.try_get("server")?;
    let database_id: Option<Uuid> = parse_optional_uuid(row, "database_id")?;
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
        id: parse_uuid(row, "id")?,
        user_id: parse_uuid(row, "user_id")?,
        target,
        action: GrantAction::parse(&action_str)?,
        constraints: row.try_get("constraints_json")?,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        revoked_at: row.try_get::<Option<DateTime<Utc>>, _>("revoked_at")?,
    })
}
