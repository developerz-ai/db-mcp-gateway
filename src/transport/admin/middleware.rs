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
//! here. Mutation handlers (POST / PATCH / DELETE) upsert it inside their own
//! transaction ([`super::audited_tx::AuditedTx`]) so the actor-row write and
//! the `permissions_audit` row are atomic. Read-only GETs never write to
//! `permissions_users` at all — a GET does not produce an audit row and
//! should not trigger a DB write.
//!
//! Every response — denial or success — carries the per-request id so a
//! failing client paste can be joined to the matching tracing span. The id
//! is the gateway-minted [`GatewayRequestId`], never a caller-supplied
//! `x-request-id`: the `permissions_audit.request_id` it ends up in must not
//! be a value the caller controls.

use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Utc;

use crate::auth::Identity;
use crate::config::AdminGroup;
use crate::transport::request_id::GatewayRequestId;

use super::error::AdminError;

/// What `require_admin_group` deposits on the request extensions for handlers.
///
/// `sub`, `email`, and `groups` carry the caller's identity so mutation
/// handlers can upsert the actor row inside their audited transaction
/// without round-tripping back to the middleware. `id` is NOT stored here:
/// it exists only once a mutation actually runs.
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
    pub admin_group: AdminGroup,
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
    let request_id = GatewayRequestId::of(&req).to_string();

    let Some(identity) = req.extensions().get::<Identity>().cloned() else {
        // `bearer_auth` either ran and rejected (so we're not here), or wasn't
        // mounted at all. Either way, no identity means we treat it as 401.
        //
        // No `permissions_audit` row: that table records permission *changes*
        // (action ∈ create/update/delete) and requires a real `actor_id` (a
        // `permissions_users.id`, not FK-enforced so audit rows outlive any
        // cleanup of the table they describe). An anonymous denial has neither — its
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

    if !identity
        .groups
        .iter()
        .any(|g| g == state.admin_group.as_str())
    {
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
        // Fail closed on an unmeasurable age. A future (or corrupt) `issued_at`
        // makes `signed_duration_since` negative, so `to_std()` errors; treat
        // that as "reject" rather than "fresh". The old `unwrap_or(max_age)`
        // fell back to exactly `max_age`, which is NOT `> max_age`, so a skewed
        // clock or a forged future timestamp bypassed the cap entirely.
        let session_age = match Utc::now()
            .signed_duration_since(identity.issued_at)
            .to_std()
        {
            Ok(age) => age,
            Err(_) => {
                tracing::warn!(
                    user_sub = %identity.user_sub,
                    request_id = %request_id,
                    max_age_secs = max_age.as_secs(),
                    "admin endpoint denied: session issued_at is in the future (403)"
                );
                return AdminError::session_too_old()
                    .with_request_id(request_id)
                    .into_response();
            }
        };
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

#[cfg(test)]
#[path = "middleware_tests.rs"]
mod tests;
