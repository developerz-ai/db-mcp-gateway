//! Request and response shapes for `/admin/v1/databases`.
//!
//! Both request DTOs declare `#[serde(deny_unknown_fields)]` so a body
//! carrying a `connection_string`, `dsn`, `password`, `role`, or any other
//! unknown field is rejected at the parse layer with `400 invalid_request`.
//! The handler never sees the field, so it can't be logged or echoed back.
//! Headline acceptance criterion from #53 — CLAUDE.md non-negotiable #1.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::permissions::PermissionsDatabase;

/// Public response shape. The storage struct never carries credentials by
/// design (migration `0004_permissions.sql` has no DSN/role/password column),
/// so this DTO cannot leak one. Kept as a dedicated type so a future schema
/// change can't quietly widen the admin surface.
#[derive(Debug, Serialize)]
pub struct DatabaseResponse {
    pub id: Uuid,
    pub server: String,
    pub db_name: String,
    pub db_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PermissionsDatabase> for DatabaseResponse {
    fn from(d: PermissionsDatabase) -> Self {
        Self {
            id: d.id,
            server: d.server,
            db_name: d.db_name,
            db_type: d.db_type.as_db_str().to_string(),
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// `deny_unknown_fields` is the security primitive. Any extra field (`dsn`,
/// `connection_string`, `password`, `role`, …) → 400 at parse time. The
/// handler never sees the unknown field; it can't be logged or echoed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDatabaseRequest {
    pub server: String,
    pub db_name: String,
    pub db_type: String,
}

/// Partial-update DTO. Same `deny_unknown_fields` discipline as create.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDatabaseRequest {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub db_name: Option<String>,
    #[serde(default)]
    pub db_type: Option<String>,
}
