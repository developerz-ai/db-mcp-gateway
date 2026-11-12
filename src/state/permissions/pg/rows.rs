//! The one set of Postgres row mappers and column lists every pg permissions
//! query shares, so a schema change has exactly one decode site.

use serde_json::Value as JsonValue;
use sqlx::Row;
use sqlx::postgres::PgRow;

use super::super::{
    DbType, GrantAction, GrantTarget, LiveGrant, PermissionsDatabase, PermissionsGrant,
    PermissionsUser, RepoError,
};

pub(super) const USER_COLUMNS: &str =
    "id, user_sub, user_email, groups, created_at, updated_at, deleted_at";

pub(super) const DATABASE_COLUMNS: &str =
    "id, server, db_name, db_type, created_at, updated_at, deleted_at";

pub(super) const GRANT_COLUMNS: &str = "id, user_id, server, database_id, db_name_wildcard, \
     action, constraints, created_at, updated_at, revoked_at";

pub(super) fn user_from_row(row: &PgRow) -> Result<PermissionsUser, RepoError> {
    let groups_json: JsonValue = row.try_get("groups")?;
    Ok(PermissionsUser {
        id: row.try_get("id")?,
        user_sub: row.try_get("user_sub")?,
        user_email: row.try_get("user_email")?,
        groups: serde_json::from_value(groups_json).map_err(RepoError::DecodeGroups)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

pub(super) fn database_from_row(row: &PgRow) -> Result<PermissionsDatabase, RepoError> {
    let db_type: String = row.try_get("db_type")?;
    Ok(PermissionsDatabase {
        id: row.try_get("id")?,
        server: row.try_get("server")?,
        db_name: row.try_get("db_name")?,
        db_type: DbType::parse(&db_type)?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        deleted_at: row.try_get("deleted_at")?,
    })
}

pub(super) fn grant_from_row(row: &PgRow) -> Result<PermissionsGrant, RepoError> {
    let action: String = row.try_get("action")?;
    Ok(PermissionsGrant {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        target: GrantTarget::from_columns(
            row.try_get("server")?,
            row.try_get("database_id")?,
            row.try_get("db_name_wildcard")?,
        )?,
        action: GrantAction::parse(&action)?,
        constraints: row.try_get("constraints")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

/// Decode the resolver join: `server` is already coalesced from the grant
/// (wildcard) or its database row (specific); `db_name` is NULL for a
/// wildcard.
pub(super) fn live_grant_from_row(row: &PgRow) -> Result<LiveGrant, RepoError> {
    let action: String = row.try_get("action")?;
    Ok(LiveGrant {
        id: row.try_get("id")?,
        server: row.try_get("server")?,
        db_name: row.try_get("db_name")?,
        action: GrantAction::parse(&action)?,
        constraints: row.try_get("constraints")?,
    })
}
