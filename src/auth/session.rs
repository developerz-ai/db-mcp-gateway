//! Sessions: the authoritative identity for an authenticated request. The
//! store that persists and caches them is [`super::session_store`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::session_cache::Inactive;
use crate::state::sessions::SessionRow;

/// Newtype over the session row UUID. Construct via `new()` or `from(Uuid)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for SessionId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<SessionId> for Uuid {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

/// Per-request identity, cloned cheaply. `auth::middleware` attaches it to
/// request extensions for handlers and the audit layer. Manual `Debug` redacts
/// `user_email` (PII); the audit writer reads it directly, nothing else should.
#[derive(Clone)]
pub struct Identity {
    pub session_id: SessionId,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    /// When the gateway issued this session. Groups are frozen at this instant
    /// — a group change in the IdP takes effect only at the *next* login.
    /// Admin middleware uses this to enforce a `session_max_age_secs` bound so
    /// operators can cap how long a stale admin-group snapshot is trusted.
    pub issued_at: DateTime<Utc>,
    pub kind: IdentityKind,
}

/// How the caller authenticated. A typed marker, not a `user_sub` prefix
/// convention: authz keys service-account behaviour off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    /// A gateway session from the SSO login.
    Sso,
    /// A static `service_accounts:` bearer (spec 14).
    Service,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("session_id", &self.session_id)
            .field("user_sub", &self.user_sub)
            .field("user_email", &"<redacted>")
            .field("groups", &self.groups)
            .field("issued_at", &self.issued_at)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Authoritative session row. `Debug` redacts `user_email` (PII) — see
/// `Identity` above for the same rationale.
#[derive(Clone)]
pub struct Session {
    pub id: SessionId,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    /// Wall-clock instant the gateway inserted this row (DB `DEFAULT now()`).
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("user_sub", &self.user_sub)
            .field("user_email", &"<redacted>")
            .field("groups", &self.groups)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl Session {
    pub fn identity(&self) -> Identity {
        Identity {
            session_id: self.id,
            user_sub: self.user_sub.clone(),
            user_email: self.user_email.clone(),
            groups: self.groups.clone(),
            issued_at: self.issued_at,
            kind: IdentityKind::Sso,
        }
    }

    /// `None` while the session may authenticate. Revocation wins over expiry
    /// so an operator sees why a session ended, not just that it did.
    pub fn inactive(&self, now: DateTime<Utc>) -> Option<Inactive> {
        if self.revoked_at.is_some() {
            Some(Inactive::Revoked)
        } else if self.expires_at <= now {
            Some(Inactive::Expired)
        } else {
            None
        }
    }
}

impl From<SessionRow> for Session {
    fn from(row: SessionRow) -> Self {
        Self {
            id: SessionId::from(row.id),
            user_sub: row.user_sub,
            user_email: row.user_email,
            groups: row.groups.0,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
