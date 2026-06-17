//! DB-backed permissions store.
//!
//! Spec: docs/initial-idea/12-dynamic-permissions.md (issues #46 / #47).
//! This module exposes the [`PermissionsRepo`] trait — the contract the admin
//! API (#52–#54) and resolver (#49) will code against — plus a Postgres impl
//! in [`pg`]. A mysql impl arrives in #50; that's the second-impl trigger that
//! justifies the trait per CLAUDE.md.
//!
//! Surface is kept minimal: dumb CRUD only. Wildcard expansion, YAML/DB merge,
//! and constraint reconciliation all live one layer up in the resolver.

pub mod pg;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use uuid::Uuid;

/// Storage backend for a registered logical database. Mirrors the
/// `permissions_databases.db_type` CHECK in migration `0004_permissions.sql`.
///
/// `mongo` is intentionally absent: this enum describes the *permissions
/// storage* schema (pg or mysql), not the *query target* type. Mongo lands as
/// a query target in #57 via [`crate::exec`]'s `DbAdapter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Postgres,
    Mysql,
}

impl DbType {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
        }
    }

    pub fn parse(s: &str) -> Result<Self, RepoError> {
        match s {
            "postgres" => Ok(Self::Postgres),
            "mysql" => Ok(Self::Mysql),
            other => Err(RepoError::UnknownDbType(other.to_string())),
        }
    }
}

/// The four actions a grant can authorize. Mirrors the
/// `permissions_grants.action` CHECK in migration `0004_permissions.sql` and
/// the four action types in spec 06 §"Actions".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAction {
    SchemaRead,
    QueryRead,
    QueryWrite,
    HistoryRead,
}

impl GrantAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::SchemaRead => "schema_read",
            Self::QueryRead => "query_read",
            Self::QueryWrite => "query_write",
            Self::HistoryRead => "history_read",
        }
    }

    pub fn parse(s: &str) -> Result<Self, RepoError> {
        match s {
            "schema_read" => Ok(Self::SchemaRead),
            "query_read" => Ok(Self::QueryRead),
            "query_write" => Ok(Self::QueryWrite),
            "history_read" => Ok(Self::HistoryRead),
            other => Err(RepoError::UnknownAction(other.to_string())),
        }
    }
}

/// What a grant points at. Encodes the XOR check from `0004_permissions.sql`
/// in the type so callers cannot construct an illegal grant (e.g. both a
/// `database_id` and a wildcard, or neither). The two variants match the two
/// legal branches of `permissions_grants_target_xor_wildcard_check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTarget {
    /// A specific row in `permissions_databases`. Server is implied by the
    /// referenced row.
    Specific { database_id: Uuid },
    /// All databases on a given server. Spec 12 §Wildcard — for dev/superuser
    /// grants; constraints still apply and a more-specific grant still merges
    /// most-restrictive-wins.
    Wildcard { server: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsUser {
    pub id: Uuid,
    pub user_sub: String,
    pub user_email: String,
    /// Group snapshot cached from the last login. JWT is the live source of
    /// truth; this is here so the admin API can list users without minting
    /// tokens for them.
    pub groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsDatabase {
    pub id: Uuid,
    pub server: String,
    pub db_name: String,
    pub db_type: DbType,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionsGrant {
    pub id: Uuid,
    pub user_id: Uuid,
    pub target: GrantTarget,
    pub action: GrantAction,
    /// Per-grant overrides for `statement_timeout_ms`, `row_limit`,
    /// `require_reason`, etc. Resolver merges these with YAML constraints
    /// most-restrictive-wins. Shape mirrors `authz::Constraints`.
    pub constraints: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("permissions db query failed")]
    Sqlx(#[from] sqlx::Error),
    #[error("row encodes unknown db_type {0:?}")]
    UnknownDbType(String),
    #[error("row encodes unknown action {0:?}")]
    UnknownAction(String),
    /// Row violates the XOR target check — should be impossible given the DB
    /// constraint, but surface it as an error rather than panicking.
    #[error("grant row violates target/wildcard XOR invariant")]
    InvalidGrantTarget {
        server: Option<String>,
        database_id: Option<Uuid>,
        wildcard: bool,
    },
    #[error("failed to encode groups JSON")]
    EncodeGroups(#[source] serde_json::Error),
    #[error("failed to decode groups JSON")]
    DecodeGroups(#[source] serde_json::Error),
}

/// CRUD surface for the permissions store. Implementations: [`pg::PgPermissionsRepo`].
///
/// Trait methods mirror the admin API verbs (#52–#54) plus the read paths the
/// resolver (#49) needs. Trait stays dumb — no constraint merging, no
/// wildcard expansion. That belongs above this layer.
#[async_trait]
pub trait PermissionsRepo: Send + Sync + std::fmt::Debug {
    /// Idempotent upsert keyed on `user_sub`. Refreshes the cached email +
    /// groups every call so the admin listing stays in sync with the JWT. A
    /// soft-deleted prior row stays as an audit trail; a fresh log-in inserts
    /// a new row rather than reviving the old one.
    async fn upsert_user(
        &self,
        user_sub: &str,
        user_email: &str,
        groups: &[String],
    ) -> Result<PermissionsUser, RepoError>;

    async fn get_user_by_sub(&self, user_sub: &str) -> Result<Option<PermissionsUser>, RepoError>;

    /// Uuid-keyed read used by the admin API (GET /admin/v1/users/:id and the
    /// PATCH read-before-write that captures `before` for the audit row).
    async fn get_user(&self, id: Uuid) -> Result<Option<PermissionsUser>, RepoError>;

    async fn list_users(&self) -> Result<Vec<PermissionsUser>, RepoError>;

    /// Partial update used by `PATCH /admin/v1/users/:id`. `None` means
    /// "leave field unchanged". Returns the post-update row, or `None` when
    /// the user is missing / soft-deleted (callers translate to 404).
    async fn update_user(
        &self,
        id: Uuid,
        user_email: Option<&str>,
        groups: Option<&[String]>,
    ) -> Result<Option<PermissionsUser>, RepoError>;

    async fn soft_delete_user(&self, id: Uuid) -> Result<bool, RepoError>;

    async fn create_database(
        &self,
        server: &str,
        db_name: &str,
        db_type: DbType,
    ) -> Result<PermissionsDatabase, RepoError>;

    async fn get_database(&self, id: Uuid) -> Result<Option<PermissionsDatabase>, RepoError>;

    async fn list_databases(&self) -> Result<Vec<PermissionsDatabase>, RepoError>;

    /// Partial update used by `PATCH /admin/v1/databases/:id`. `None` means
    /// "leave field unchanged". Returns the post-update row, or `None` when
    /// the database is missing / soft-deleted (callers translate to 404).
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
        constraints: JsonValue,
    ) -> Result<PermissionsGrant, RepoError>;

    /// Resolver's lookup path. Returns only live (non-revoked) grants.
    async fn list_grants_for_user(&self, user_id: Uuid)
    -> Result<Vec<PermissionsGrant>, RepoError>;

    async fn revoke_grant(&self, id: Uuid) -> Result<bool, RepoError>;
}
