//! `POST /admin/v1/users/:id/revoke-sessions` — operator kill switch for one
//! subject: every live session and refresh chain, in one audited
//! transaction (plan 101 slice 08 step 2).
//!
//! Audited as an `update` of the user row: the `permissions_audit` CHECKs
//! admit only create/update/delete, and the change *is* to that subject's
//! state. The payload is told apart from a profile update by its
//! `live_sessions` key.

use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Extension, Path, State};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::audit::permissions::{PermissionsAuditAction, PermissionsAuditTargetType};
use crate::auth::SessionStore;
use crate::state::oauth::delete_refresh_tokens_for_sub;
use crate::state::permissions::pg::users;

use super::super::audited_tx::AuditedTx;
use super::super::error::AdminError;
use super::super::middleware::AdminActor;
use super::super::validation::{internal, invalid_id, not_found, store_error};
use super::UsersState;
use super::handlers::lock_actor_unless_self;

#[derive(Debug, Serialize)]
pub struct RevokeSessionsResponse {
    pub revoked_sessions: usize,
    pub revoked_refresh_tokens: u64,
}

pub async fn revoke_sessions(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<RevokeSessionsResponse>, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("user", rid))?;

    let mut atx = AuditedTx::begin(&state.state_db, &actor).await?;
    let is_self = lock_actor_unless_self(&mut atx, &actor, id).await?;
    let user = users::tx_lock_user(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_user", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    if is_self {
        atx.actor_is(user.id);
    }
    let revoked = SessionStore::revoke_all_for_sub_in(atx.tx(), &user.user_sub)
        .await
        .map_err(|err| internal("revoke_sessions", err, rid))?;
    let refresh = delete_refresh_tokens_for_sub(&mut **atx.tx(), &user.user_sub)
        .await
        .map_err(|err| internal("revoke_refresh_tokens", err, rid))?;
    let before = json!({
        "user_sub": user.user_sub,
        "live_sessions": revoked.len(),
        "refresh_tokens": refresh,
    });
    let after = json!({ "user_sub": user.user_sub, "live_sessions": 0, "refresh_tokens": 0 });
    let (action, target) = (
        PermissionsAuditAction::Update,
        PermissionsAuditTargetType::User,
    );
    atx.audit(action, target, id, Some(before), Some(after))
        .await?;
    // Grants are untouched, so no cached grant set changes.
    atx.commit(&state.cache, None).await?;
    // Tombstone only after commit: a rolled-back revoke must not log anyone out.
    state.sessions.committed(None, &revoked).await;

    Ok(Json(RevokeSessionsResponse {
        revoked_sessions: revoked.len(),
        revoked_refresh_tokens: refresh,
    }))
}
