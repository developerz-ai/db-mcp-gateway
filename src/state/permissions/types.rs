//! Row and value types shared by both permissions-store backends.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use super::RepoError;

/// Kind of the *target* database a `permissions_databases` row registers —
/// the engine the gateway queries, not the store this row lives in. Mirrors
/// the `permissions_databases.db_type` CHECK (pg `0013`, mysql `0005`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Postgres,
    Mysql,
    Mongo,
}

impl DbType {
    pub const ALLOWED: &'static str = "postgres, mysql, mongo";

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Mongo => "mongo",
        }
    }

    pub fn parse(s: &str) -> Result<Self, RepoError> {
        match s {
            "postgres" => Ok(Self::Postgres),
            "mysql" => Ok(Self::Mysql),
            "mongo" => Ok(Self::Mongo),
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
/// `database_id` and a wildcard, or neither).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantTarget {
    /// A specific row in `permissions_databases`. Server is implied by the
    /// referenced row.
    Specific { database_id: Uuid },
    /// Every database the gateway *config* declares on `server` — not every
    /// registered `permissions_databases` row (spec 12 §Wildcard).
    Wildcard { server: String },
}

impl GrantTarget {
    /// Split into the `(server, database_id, db_name_wildcard)` column triple.
    pub fn columns(&self) -> (Option<&str>, Option<Uuid>, bool) {
        match self {
            Self::Specific { database_id } => (None, Some(*database_id), false),
            Self::Wildcard { server } => (Some(server), None, true),
        }
    }

    /// Rebuild from the column triple; anything but the two legal branches
    /// is a corrupt row.
    pub fn from_columns(
        server: Option<String>,
        database_id: Option<Uuid>,
        wildcard: bool,
    ) -> Result<Self, RepoError> {
        match (server, database_id, wildcard) {
            (None, Some(database_id), false) => Ok(Self::Specific { database_id }),
            (Some(server), None, true) => Ok(Self::Wildcard { server }),
            (server, database_id, wildcard) => Err(RepoError::InvalidGrantTarget {
                server,
                database_id,
                wildcard,
            }),
        }
    }
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
    /// Per-grant `require_reason` / `row_limit` / `statement_timeout_ms`.
    /// Shape mirrors `config::Constraints`; the resolver merges it
    /// most-restrictive-wins.
    pub constraints: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// One live grant resolved for the authz loader: user live, grant not
/// revoked, and — for a specific grant — its database row live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveGrant {
    pub id: Uuid,
    pub server: String,
    /// `None` = wildcard over the server's config databases.
    pub db_name: Option<String>,
    pub action: GrantAction,
    pub constraints: JsonValue,
}

/// A bounded window over a list endpoint's results.
///
/// The admin list queries used to `fetch_all` with no `LIMIT` (#136). A bare
/// cap would return a silently incomplete list; paging is explicit about
/// there being more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    limit: i64,
    offset: i64,
}

impl Page {
    /// Rows returned when the caller doesn't ask for a specific `limit`.
    pub const DEFAULT_LIMIT: u32 = 100;
    /// Hard ceiling on `limit`; an oversized ask is clamped, not rejected.
    pub const MAX_LIMIT: u32 = 1000;

    /// Clamp caller input into a usable window. `limit` lands in
    /// `1..=MAX_LIMIT` — zero would burn a round trip to return nothing.
    pub fn new(limit: Option<u32>, offset: Option<u32>) -> Self {
        let limit = limit
            .unwrap_or(Self::DEFAULT_LIMIT)
            .clamp(1, Self::MAX_LIMIT);
        Self {
            limit: i64::from(limit),
            offset: i64::from(offset.unwrap_or(0)),
        }
    }

    /// Bind value for `LIMIT` (`i64` is what both Postgres and MySQL want).
    pub fn limit(self) -> i64 {
        self.limit
    }

    pub fn offset(self) -> i64 {
        self.offset
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::new(None, None)
    }
}

/// A committed permissions change, as far as the authz cache cares: which
/// cached grant sets it can have affected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionsChange {
    /// Only this `user_sub`'s grant set.
    User(String),
    /// Any user's — e.g. a database row change, or notifications were lost.
    All,
}

impl PermissionsChange {
    const USER_PREFIX: &'static str = "user:";
    const ALL: &'static str = "all";

    /// Wire form for `NOTIFY`.
    pub fn encode(&self) -> String {
        match self {
            Self::User(sub) => format!("{}{sub}", Self::USER_PREFIX),
            Self::All => Self::ALL.to_string(),
        }
    }

    /// Anything unrecognised decodes to `All`: a stale cache is the failure
    /// to avoid, an extra reload is not.
    pub fn decode(payload: &str) -> Self {
        match payload.strip_prefix(Self::USER_PREFIX) {
            Some(sub) if !sub.is_empty() => Self::User(sub.to_string()),
            _ => Self::All,
        }
    }
}
