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

mod databases;
mod grants;
mod rows;
mod users;

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::MySqlPool;
use uuid::Uuid;

use super::{
    DbType, GrantAction, GrantTarget, Page, PermissionsDatabase, PermissionsGrant, PermissionsRepo,
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
        users::upsert_user(&self.pool, user_sub, user_email, groups).await
    }

    async fn get_user_by_sub(&self, user_sub: &str) -> Result<Option<PermissionsUser>, RepoError> {
        users::get_user_by_sub(&self.pool, user_sub).await
    }

    async fn get_user(&self, id: Uuid) -> Result<Option<PermissionsUser>, RepoError> {
        users::get_user(&self.pool, id).await
    }

    async fn update_user(
        &self,
        id: Uuid,
        user_email: Option<&str>,
        groups: Option<&[String]>,
    ) -> Result<Option<PermissionsUser>, RepoError> {
        users::update_user(&self.pool, id, user_email, groups).await
    }

    async fn list_users(&self, page: Page) -> Result<Vec<PermissionsUser>, RepoError> {
        users::list_users(&self.pool, page).await
    }

    async fn soft_delete_user(&self, id: Uuid) -> Result<bool, RepoError> {
        users::soft_delete_user(&self.pool, id).await
    }

    async fn create_database(
        &self,
        server: &str,
        db_name: &str,
        db_type: DbType,
    ) -> Result<PermissionsDatabase, RepoError> {
        databases::create_database(&self.pool, server, db_name, db_type).await
    }

    async fn get_database(&self, id: Uuid) -> Result<Option<PermissionsDatabase>, RepoError> {
        databases::get_database(&self.pool, id).await
    }

    async fn list_databases(&self, page: Page) -> Result<Vec<PermissionsDatabase>, RepoError> {
        databases::list_databases(&self.pool, page).await
    }

    async fn all_live_databases(&self) -> Result<Vec<PermissionsDatabase>, RepoError> {
        databases::all_live_databases(&self.pool).await
    }

    async fn update_database(
        &self,
        id: Uuid,
        server: Option<&str>,
        db_name: Option<&str>,
        db_type: Option<DbType>,
    ) -> Result<Option<PermissionsDatabase>, RepoError> {
        databases::update_database(&self.pool, id, server, db_name, db_type).await
    }

    async fn soft_delete_database(&self, id: Uuid) -> Result<bool, RepoError> {
        databases::soft_delete_database(&self.pool, id).await
    }

    async fn create_grant(
        &self,
        user_id: Uuid,
        target: GrantTarget,
        action: GrantAction,
        constraints: JsonValue,
    ) -> Result<PermissionsGrant, RepoError> {
        grants::create_grant(&self.pool, user_id, target, action, constraints).await
    }

    async fn list_grants_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        grants::list_grants_for_user(&self.pool, user_id).await
    }

    async fn get_grant(&self, id: Uuid) -> Result<Option<PermissionsGrant>, RepoError> {
        grants::get_grant(&self.pool, id).await
    }

    async fn list_grants(
        &self,
        user_id: Option<Uuid>,
        database_id: Option<Uuid>,
        page: Page,
    ) -> Result<Vec<PermissionsGrant>, RepoError> {
        grants::list_grants(&self.pool, user_id, database_id, page).await
    }

    async fn update_grant(
        &self,
        id: Uuid,
        action: Option<GrantAction>,
        constraints: Option<JsonValue>,
    ) -> Result<Option<PermissionsGrant>, RepoError> {
        grants::update_grant(&self.pool, id, action, constraints).await
    }

    async fn revoke_grant(&self, id: Uuid) -> Result<bool, RepoError> {
        grants::revoke_grant(&self.pool, id).await
    }
}
