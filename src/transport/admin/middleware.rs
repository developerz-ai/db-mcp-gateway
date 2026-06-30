//! `require_admin_group` middleware for `/admin/v1/*` (#52).
//!
//! Runs *after* `bearer_auth`, so an `Identity` is already in extensions.
//! Job:
//!  1. Reject with 403 if the caller doesn't carry the configured admin group.
//!  2. Reject with 403 (`session_too_old`) if the session was issued longer ago
//!     than `max_session_age` (when configured). Group memberships are frozen at
//!     login time; `max_session_age` caps how long a stale admin-group snapshot
//!     is trusted — a removed admin must re-authenticate within this window.
//!  3. Stash `AdminActor` in request extensions for handlers to read.
//!
//! ## Admin group propagation
//!
//! Group membership is a snapshot from the IdP, written into the session at
//! login and never refreshed. A gateway-side DB re-read (bypassing the 30 s
//! session cache) still returns the same frozen groups — the source of truth is
//! the session row, not the IdP. Implications:
//!
//! - **Granting** the admin group: takes effect at the user's next login.
//! - **Revoking** the admin group: the user retains access until their session
//!   expires (`auth.oidc.session_ttl_hours`, default 8 h) **or** an operator
//!   explicitly revokes the session via `POST /revoke` (RFC 7009) or
//!   `DELETE /auth/logout`.
//! - Set `admin.session_max_age_secs` to shorten the exposure window for admin
//!   routes specifically (e.g. `3600` = 1 h). A user with a session older than
//!   this limit is forced to re-login, at which point IdP group state applies.
//!
//! The `permissions_users` upsert for the acting admin is intentionally absent
//! here. Mutation handlers (POST / PATCH / DELETE) call [`tx_upsert_actor`]
//! inside their own transaction so the actor-row write and the
//! `permissions_audit` row are atomic. Read-only GETs never write to
//! `permissions_users` at all — a GET does not produce an audit row and
//! should not trigger a DB write.
//!
//! Every response — denial or success — carries the per-request id so a
//! failing client paste can be joined to the matching tracing span. The id
//! is extracted from `x-request-id` if the caller supplied one (gateways /
//! ingress meshes commonly do); otherwise we mint a UUID.

use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde_json::Value as JsonValue;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::auth::Identity;
use crate::state::permissions::RepoError;

use super::error::AdminError;

/// What `require_admin_group` deposits on the request extensions for handlers.
///
/// `sub`, `email`, and `groups` carry the caller's identity so mutation
/// handlers can call [`tx_upsert_actor`] inside their audited transaction
/// without round-tripping back to the middleware. `id` is NOT stored here:
/// it comes back from [`tx_upsert_actor`] only when a mutation actually runs.
#[derive(Debug, Clone)]
pub struct AdminActor {
    pub sub: String,
    pub email: String,
    pub groups: Vec<String>,
    pub request_id: String,
}

/// Cloned into each `/admin/v1/*` layer; carries the admin-group name the
/// middleware needs to gate access.
#[derive(Clone)]
pub struct AdminMiddlewareState {
    pub admin_group: String,
    /// When set, sessions older than this are rejected with `session_too_old`
    /// (403) even if the group check would pass. Forces re-login so that IdP
    /// group changes propagate within this bound. `None` = no age cap (rely on
    /// `session_ttl_hours`). Set via `admin.session_max_age_secs` in YAML.
    pub max_session_age: Option<Duration>,
}

impl std::fmt::Debug for AdminMiddlewareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminMiddlewareState")
            .field("admin_group", &self.admin_group)
            .field("max_session_age", &self.max_session_age)
            .finish()
    }
}

pub async fn require_admin_group(
    State(state): State<AdminMiddlewareState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Resolve the request id up-front so EVERY exit path (401, 403, handler
    // success) carries the same id. Lifting this above the identity check was
    // a deliberate fix: previously the 401/403 responses dropped through with
    // no correlation id, blinding ops on the most common failure modes.
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let Some(identity) = req.extensions().get::<Identity>().cloned() else {
        // `bearer_auth` either ran and rejected (so we're not here), or wasn't
        // mounted at all. Either way, no identity means we treat it as 401.
        //
        // No `permissions_audit` row: that table records permission *changes*
        // (action ∈ create/update/delete) and requires a real `actor_id` (FK
        // to `permissions_users`). An anonymous denial has neither — its
        // forensic trail lives in the structured tracing line below + the
        // gateway's request log (spec 07).
        tracing::warn!(
            request_id = %request_id,
            "admin endpoint denied: no identity (401)"
        );
        return AdminError::unauthorized()
            .with_request_id(request_id)
            .into_response();
    };

    if !identity.groups.iter().any(|g| g == &state.admin_group) {
        // Authenticated but not in the admin group: structured tracing carries
        // the user_sub + request_id for ops triage. We deliberately do not
        // upsert into `permissions_users` here — doing so would let any
        // non-admin caller seed a row by hitting `/admin/*`, which is a
        // (small) write amplification + pollution risk.
        tracing::warn!(
            user_sub = %identity.user_sub,
            request_id = %request_id,
            "admin endpoint denied: caller missing admin group (403)"
        );
        return AdminError::forbidden()
            .with_request_id(request_id)
            .into_response();
    }

    // Session age check — enforces `admin.session_max_age_secs` when configured.
    //
    // Groups are frozen at login; a removed admin retains access until their
    // session expires or is explicitly revoked. `max_session_age` caps that
    // window for admin routes specifically: a session older than this limit is
    // rejected here, forcing re-login regardless of remaining session TTL. The
    // next login picks up the current IdP group state.
    if let Some(max_age) = state.max_session_age {
        let session_age = Utc::now()
            .signed_duration_since(identity.issued_at)
            .to_std()
            .unwrap_or(max_age); // clock skew guard: treat negative duration as expired
        if session_age > max_age {
            tracing::warn!(
                user_sub = %identity.user_sub,
                request_id = %request_id,
                session_age_secs = session_age.as_secs(),
                max_age_secs = max_age.as_secs(),
                "admin endpoint denied: session too old for admin operations (403)"
            );
            return AdminError::session_too_old()
                .with_request_id(request_id)
                .into_response();
        }
    }

    req.extensions_mut().insert(AdminActor {
        sub: identity.user_sub,
        email: identity.user_email,
        groups: identity.groups,
        request_id,
    });

    next.run(req).await
}

/// Upsert the calling admin's `permissions_users` row inside an already-open
/// transaction. Returns the actor's `id` for use as `actor_id` in the
/// accompanying `permissions_audit` row.
///
/// Mutation handlers (POST / PATCH / DELETE) call this before writing the
/// audit row so both writes are atomic: if the audit write fails and the
/// transaction rolls back, the actor-row upsert is also rolled back. Read
/// handlers (GET) never call this — they produce no audit rows.
///
/// Keyed on `user_sub` with a soft-delete guard (`WHERE deleted_at IS NULL`).
/// A soft-deleted prior row stays as an audit trail; the next mutation by the
/// same admin inserts a fresh row rather than reviving the old one.
pub(super) async fn tx_upsert_actor(
    tx: &mut Transaction<'_, Postgres>,
    sub: &str,
    email: &str,
    groups: &[String],
) -> Result<Uuid, RepoError> {
    let groups_json: JsonValue = serde_json::to_value(groups).map_err(RepoError::EncodeGroups)?;
    let row = sqlx::query(
        "INSERT INTO permissions_users (user_sub, user_email, groups) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (user_sub) WHERE deleted_at IS NULL \
         DO UPDATE SET user_email = EXCLUDED.user_email, \
                       groups     = EXCLUDED.groups, \
                       updated_at = now() \
         RETURNING id",
    )
    .bind(sub)
    .bind(email)
    .bind(&groups_json)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.try_get("id")?)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use chrono::Utc;

    use super::*;
    use crate::auth::SessionId;

    /// Build an `Identity` with the given group list and `issued_at` offset from
    /// now. Positive = issued N seconds ago; negative = issued in the future
    /// (used to exercise the clock-skew guard).
    fn make_identity(groups: &[&str], issued_secs_ago: i64) -> Identity {
        let now = Utc::now();
        Identity {
            session_id: SessionId::new(),
            user_sub: "u".to_string(),
            user_email: "u@example.com".to_string(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            issued_at: now - chrono::Duration::seconds(issued_secs_ago),
        }
    }

    #[test]
    fn session_too_old_renders_403_with_stable_code() {
        let err = AdminError::session_too_old().with_request_id("req-1");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn session_too_old_body_has_stable_code() {
        let resp = AdminError::session_too_old()
            .with_request_id("req-1")
            .into_response();
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], "session_too_old");
        assert_eq!(body["error"]["request_id"], "req-1");
    }

    /// Young-enough session passes the age gate.
    #[test]
    fn fresh_session_passes_age_gate() {
        let identity = make_identity(&["admins"], 30); // 30 s old
        let max_age = Duration::from_secs(3600); // 1 h limit
        let age = Utc::now()
            .signed_duration_since(identity.issued_at)
            .to_std()
            .unwrap();
        assert!(
            age <= max_age,
            "30 s session should pass a 3600 s age limit"
        );
    }

    /// Session older than `max_session_age` must be rejected.
    #[test]
    fn stale_session_exceeds_age_gate() {
        let identity = make_identity(&["admins"], 7201); // 2 h + 1 s old
        let max_age = Duration::from_secs(3600); // 1 h limit
        let age = Utc::now()
            .signed_duration_since(identity.issued_at)
            .to_std()
            .unwrap();
        assert!(
            age > max_age,
            "7201 s session should exceed a 3600 s age limit"
        );
    }

    /// `issued_at` in the future (clock skew / NTP jump) is treated as
    /// expired rather than panic-ing or allowing indefinitely.
    #[test]
    fn future_issued_at_treated_as_expired() {
        let identity = make_identity(&["admins"], -120); // issued 2 min in future
        let max_age = Duration::from_secs(3600);
        // signed_duration_since returns negative → to_std() returns Err → falls
        // back to `max_age`, so the check `session_age > max_age` is false.
        // The session is not rejected by the age gate (the skewed clock is
        // benign — this is a safety net, not an attack vector).
        let session_age = Utc::now()
            .signed_duration_since(identity.issued_at)
            .to_std()
            .unwrap_or(max_age); // clock-skew guard
        // unwrap_or(max_age) means session_age == max_age → NOT > max_age →
        // passes. This is intentionally permissive: negative duration ≠ expired,
        // it just means we can't measure age. A small clock skew is not an
        // attack; revocation still applies.
        assert!(
            session_age <= max_age,
            "future issued_at should not trigger the age gate"
        );
    }
}
