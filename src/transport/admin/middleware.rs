//! `require_admin_group` middleware for `/admin/v1/*` (#52).
//!
//! Runs *after* `bearer_auth`, so an `Identity` is already in extensions.
//! Job:
//!  1. Reject with 403 if the caller doesn't carry the configured admin group.
//!  2. Stash `AdminActor` in request extensions for handlers to read.
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

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
}

impl std::fmt::Debug for AdminMiddlewareState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminMiddlewareState")
            .field("admin_group", &self.admin_group)
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
