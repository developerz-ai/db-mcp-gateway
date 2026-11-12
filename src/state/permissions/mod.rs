//! DB-backed permissions store.
//!
//! Spec: website/docs/initial-idea/12-dynamic-permissions.md. Two halves:
//!
//! - [`PermissionsRepo`] — the pool-backed **read** surface the admin GETs and
//!   the authz resolver code against. Implemented by [`pg::PgPermissionsRepo`]
//!   and [`mysql::MysqlPermissionsRepo`].
//! - [`pg`]'s `tx_*` functions — every **write**, each taking an open
//!   `&mut Transaction<Postgres>` so the admin layer commits it together with
//!   its `permissions_audit` row. There is no pool-backed production write:
//!   an unaudited permissions change has no code path.
//!
//! The MySQL store is read-only-provisioned: it is filled by the operator's
//! own tooling, and boot rejects `driver: mysql` with `admin.enabled`.
//! [`PermissionsSeed`] exists only so tests can fill either store.
//!
//! Surface is kept dumb: wildcard expansion, YAML/DB merge, and constraint
//! reconciliation all live one layer up in `authz`.

mod error;
pub mod mysql;
pub mod pg;
mod types;

pub use error::RepoError;
pub use types::{
    DbType, GrantAction, GrantTarget, LiveGrant, Page, PermissionsChange, PermissionsDatabase,
    PermissionsGrant, PermissionsUser,
};

use async_trait::async_trait;
use uuid::Uuid;

/// Read surface of the permissions store.
#[async_trait]
pub trait PermissionsRepo: Send + Sync + std::fmt::Debug {
    /// Live user by row id; `None` when missing or soft-deleted.
    async fn get_user(&self, id: Uuid) -> Result<Option<PermissionsUser>, RepoError>;

    /// One page of live users, `created_at, id` order.
    async fn list_users(&self, page: Page) -> Result<Vec<PermissionsUser>, RepoError>;

    async fn get_database(&self, id: Uuid) -> Result<Option<PermissionsDatabase>, RepoError>;

    /// One page of live databases, `server, db_name` order.
    async fn list_databases(&self, page: Page) -> Result<Vec<PermissionsDatabase>, RepoError>;

    /// Live grant by id; `None` when missing or revoked.
    async fn get_grant(&self, id: Uuid) -> Result<Option<PermissionsGrant>, RepoError>;

    /// Admin list with optional filters. `database_id` matches only
    /// `Specific` grants — a wildcard has no `database_id`.
    async fn list_grants(
        &self,
        user_id: Option<Uuid>,
        database_id: Option<Uuid>,
        page: Page,
    ) -> Result<Vec<PermissionsGrant>, RepoError>;

    /// The resolver's one round trip: every live grant of the live user
    /// `user_sub`, specific grants joined to their live database row.
    ///
    /// Unpaginated on purpose — the result *is* the caller's authority, so a
    /// window would silently revoke grants. Bounded by grants-per-user, which
    /// an admin controls.
    async fn live_grants_for_sub(&self, user_sub: &str) -> Result<Vec<LiveGrant>, RepoError>;
}

/// Direct pool writes for test fixtures only. Production writes go through
/// the transactional `pg::*::tx_*` functions, audited by the admin layer.
#[cfg(any(test, feature = "test-support"))]
#[async_trait]
pub trait PermissionsSeed: PermissionsRepo {
    async fn upsert_user(
        &self,
        user_sub: &str,
        user_email: &str,
        groups: &[String],
    ) -> Result<PermissionsUser, RepoError>;

    async fn get_user_by_sub(&self, user_sub: &str) -> Result<Option<PermissionsUser>, RepoError>;

    async fn soft_delete_user(&self, id: Uuid) -> Result<bool, RepoError>;

    async fn create_database(
        &self,
        server: &str,
        db_name: &str,
        db_type: DbType,
    ) -> Result<PermissionsDatabase, RepoError>;

    async fn update_database(
        &self,
        id: Uuid,
        server: Option<&str>,
        db_name: Option<&str>,
        db_type: Option<DbType>,
    ) -> Result<Option<PermissionsDatabase>, RepoError>;

    async fn soft_delete_database(&self, id: Uuid) -> Result<bool, RepoError>;

    async fn create_grant(
        &self,
        user_id: Uuid,
        target: GrantTarget,
        action: GrantAction,
        constraints: serde_json::Value,
    ) -> Result<PermissionsGrant, RepoError>;

    /// Live grants of `user_id`, `created_at` order.
    async fn list_grants_for_user(&self, user_id: Uuid)
    -> Result<Vec<PermissionsGrant>, RepoError>;

    async fn revoke_grant(&self, id: Uuid) -> Result<bool, RepoError>;
}
