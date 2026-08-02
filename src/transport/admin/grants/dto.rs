//! Request and response shapes for `/admin/v1/grants`.
//!
//! Both request DTOs declare `#[serde(deny_unknown_fields)]` so an attempt to
//! sneak unsupported fields through (e.g. a hypothetical `priority` knob the
//! spec deliberately rejected — see [spec 12 §"Two sources, one engine"])
//! produces `400 invalid_request` at parse time. Same DSN-rejection
//! discipline as the databases endpoint: the handler never sees an unknown
//! field, so it can't be logged or echoed.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::config::Constraints;
use crate::state::permissions::{GrantTarget, Page, PermissionsGrant};

/// `GrantTarget` is an XOR in the storage schema (migration 0004's
/// `permissions_grants_target_xor_wildcard_check`): exactly one of
/// `database_id` (Specific) or `(server, db_name_wildcard=true)` (Wildcard).
/// The DTO models BOTH branches as optional fields so the JSON shape stays
/// close to spec 12's request example; the handler picks the right variant
/// via [`super::validation::parse_grant_target`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGrantRequest {
    pub user_id: Uuid,
    #[serde(default)]
    pub database_id: Option<Uuid>,
    #[serde(default)]
    pub server: Option<String>,
    /// Only valid when `server` is set and `database_id` is absent. The
    /// validator enforces this; the storage CHECK is the safety net.
    #[serde(default)]
    pub db_name_wildcard: Option<bool>,
    pub action: String,
    /// `Constraints` itself uses `deny_unknown_fields` (see #16's typo work
    /// in `src/config/schema.rs`), so a misspelled key inside this nested
    /// object surfaces with serde's standard error envelope rather than
    /// being silently accepted.
    #[serde(default)]
    pub constraints: Constraints,
}

/// PATCH only touches the **mutable** fields. The target (Specific vs
/// Wildcard) is the grant's identity — changing it would functionally be a
/// different grant. To re-target, callers DELETE then POST. `deny_unknown_fields`
/// enforces this: attempting to send `database_id`/`server`/`db_name_wildcard`
/// via PATCH returns `400 invalid_request`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateGrantRequest {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub constraints: Option<Constraints>,
}

/// Public response shape. Mirrors `permissions_grants` rows; storage carries
/// no credentials by design (#47), so DTO can't leak any.
#[derive(Debug, Serialize)]
pub struct GrantResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    /// Set when `target` is `Specific`; `None` for `Wildcard` grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_id: Option<Uuid>,
    /// Set when `target` is `Wildcard`; `None` for `Specific` grants.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub db_name_wildcard: bool,
    pub action: String,
    pub constraints: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PermissionsGrant> for GrantResponse {
    fn from(g: PermissionsGrant) -> Self {
        let (database_id, server, db_name_wildcard) = match &g.target {
            GrantTarget::Specific { database_id } => (Some(*database_id), None, false),
            GrantTarget::Wildcard { server } => (None, Some(server.clone()), true),
        };
        Self {
            id: g.id,
            user_id: g.user_id,
            database_id,
            server,
            db_name_wildcard,
            action: g.action.as_db_str().to_string(),
            constraints: g.constraints,
            created_at: g.created_at,
            updated_at: g.updated_at,
        }
    }
}

/// `?user_id=&database_id=` filter for `GET /admin/v1/grants`, plus the shared
/// `?limit=&offset=` pagination window. Bad UUIDs surface via Axum's `Query`
/// rejection — translated to `invalid_request` by the handler.
///
/// All four fields sit at the top level rather than pulling `limit`/`offset`
/// in via `#[serde(flatten)] PageQuery`: serde documents that
/// `deny_unknown_fields` is silently disabled by `flatten` (unknown keys leak
/// through into the flattened map), which would let a typo like `?usr_id=`
/// bypass the stable `invalid_request` rejection. Keep it inline so the
/// unknown-field guard actually fires.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListGrantsQuery {
    #[serde(default)]
    pub user_id: Option<Uuid>,
    #[serde(default)]
    pub database_id: Option<Uuid>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

impl ListGrantsQuery {
    /// Build the validated pagination window at the transport boundary — same
    /// clamp/default semantics as [`super::super::page_query::PageQuery::to_page`].
    pub fn to_page(&self) -> Page {
        Page::new(self.limit, self.offset)
    }
}
