use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{Row, mysql::MySqlRow};
use uuid::Uuid;

use super::super::{
    DbType, GrantAction, GrantTarget, PermissionsDatabase, PermissionsGrant, PermissionsUser,
    RepoError,
};

/// Decode a CHAR(36) UUID column. The pg impl reads `UUID` natively;
/// mysql stores them as strings (no native UUID type until 8.0.13+),
/// so we parse on the way out.
pub(super) fn parse_uuid(row: &MySqlRow, column: &str) -> Result<Uuid, RepoError> {
    let s: String = row.try_get(column)?;
    Uuid::parse_str(&s).map_err(|_| {
        RepoError::Sqlx(sqlx::Error::Decode(
            format!("invalid uuid in column `{column}`").into(),
        ))
    })
}

pub(super) fn parse_optional_uuid(row: &MySqlRow, column: &str) -> Result<Option<Uuid>, RepoError> {
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

pub(super) fn user_from_row(row: &MySqlRow) -> Result<PermissionsUser, RepoError> {
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

pub(super) fn database_from_row(row: &MySqlRow) -> Result<PermissionsDatabase, RepoError> {
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

pub(super) fn grant_from_row(row: &MySqlRow) -> Result<PermissionsGrant, RepoError> {
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
