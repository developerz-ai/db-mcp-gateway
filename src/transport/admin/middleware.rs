//! `require_admin_group` middleware for `/admin/v1/*` (#52).
//!
//! Runs *after* `bearer_auth`, so an `Identity` is already in extensions.
//! Job:
//!  1. Reject with 403 if the caller doesn't carry the configured admin group.
//!  2. Upsert the calling admin into `permissions_users` so audit rows can
//!     reference a real `actor_id`. Spec 12 §"Open questions" defers cold
//!     bootstrap to a CLI subcommand; an already-admin caller (group claim
//!     present) gets their row auto-provisioned here.
//!  3. Stash `AdminActor` in request extensions for handlers to read.
//!
//! Every response — denial or success — carries the per-request id so a
//! failing client paste can be joined to the matching tracing span. The id
//! is extracted from `x-request-id` if the caller supplied one (gateways /
//! ingress meshes commonly do); otherwise we mint a UUID.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::auth::Identity;
use crate::state::permissions::PermissionsRepo;

use super::error::AdminError;

/// What `require_admin_group` deposits on the request extensions for handlers.
/// Carries the audit-row primary key (`actor_id`), the email for denormalized
/// audit storage, and the per-request id threaded into every audit row.
#[derive(Debug, Clone)]
pub struct AdminActor {
    pub id: Uuid,
    pub email: String,
    pub request_id: String,
}

/// Cloned into each `/admin/v1/*` layer; carries the admin-group name + the
/// repo handle the middleware needs to upsert the calling admin.
#[derive(Clone)]
pub struct AdminMiddlewareState {
    pub admin_group: String,
    pub repo: Arc<dyn PermissionsRepo>,
}

impl std::fmt::Debug for AdminMiddlewareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminMiddlewareState")
            .field("admin_group", &self.admin_group)
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .finish()
    }
}

pub async fn require_admin_group(
    State(state): State<AdminMiddlewareState>,
    mut req: Request,
    next: Next,
) -> Response {
    // Resolve the request id up-front so EVERY exit path (401, 403, upsert
    // failure, handler success) carries the same id. Lifting this above the
    // identity check was a deliberate fix: previously the 401/403 responses
    // dropped through with no correlation id, blinding ops on the most
    // common failure modes.
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
        // the user_sub + request_id for ops triage. We deliberately don't
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

    // Upsert keeps the admin's `permissions_users` row in sync with the JWT.
    // This is the only path that writes to that table for the admin
    // themselves — spec 12 cold-start uses a CLI subcommand (out of #52).
    let user = match state
        .repo
        .upsert_user(&identity.user_sub, &identity.user_email, &identity.groups)
        .await
    {
        Ok(u) => u,
        Err(err) => {
            // Same shape as users::internal — log only the error TYPE, never
            // the Display text. A `sqlx::Error::Database` `Display` embeds PG
            // `detail`/`constraint`, which on `permissions_users` would leak
            // user emails and group names. CLAUDE.md non-negotiable #1.
            let error_type = std::any::type_name_of_val(&err);
            tracing::error!(
                error_type,
                user_sub = %identity.user_sub,
                request_id = %request_id,
                "admin actor upsert failed"
            );
            return AdminError::internal()
                .with_request_id(request_id)
                .into_response();
        }
    };

    req.extensions_mut().insert(AdminActor {
        id: user.id,
        email: identity.user_email.clone(),
        request_id,
    });

    next.run(req).await
}
