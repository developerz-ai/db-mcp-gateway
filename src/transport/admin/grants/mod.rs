//! `/admin/v1/grants` handlers (#54).
//!
//! Grants are the actual `(user, target, action, constraints)` mapping the
//! authz engine reads. CRUD here flows through the same tx-wrapped data+audit
//! pattern as users/databases plus a **cache invalidation hook**: every
//! successful write fires [`PermissionsCache::invalidate`] for the affected
//! user_sub so the next tool call sees the change without a restart. That's
//! the headline acceptance from #54: "Live grant change is reflected on the
//! next tool call."
//!
//! ## XOR target
//!
//! [`GrantTarget`] is XOR in the storage schema: exactly one of
//! `Specific { database_id }` or `Wildcard { server }`. The request DTO
//! exposes both as optional fields (matches spec 12's example payload) and
//! [`validation::parse_grant_target`] enforces the XOR with stable
//! `invalid_request` errors. PATCH cannot change the target — that's the
//! grant's identity; re-target by DELETE + POST.
//!
//! ## File layout
//!
//! Split across submodules to keep each file under the CLAUDE.md 300-LOC
//! ceiling: [`dto`] for request/response shapes, [`sql`] for the tx-scoped
//! SQL helpers, [`validation`] for input parsing + error mapping. This file
//! owns only the route handlers.

mod dto;
mod sql;
mod validation;

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::permissions::{
    self, PermissionsAuditAction, PermissionsAuditRow, PermissionsAuditTargetType,
};
use crate::authz::PermissionsCache;
use crate::state::permissions::PermissionsRepo;

use super::error::AdminError;
use super::middleware::{AdminActor, tx_upsert_actor};

pub use dto::{CreateGrantRequest, GrantResponse, ListGrantsQuery, UpdateGrantRequest};

use sql::{
    tx_create_grant, tx_get_grant_by_id, tx_revoke_grant, tx_update_grant, tx_user_sub_for_id,
};
use validation::{
    constraints_to_json, grant_payload, internal, invalid_body, invalid_id, invalid_query,
    map_create_grant_error, parse_action, parse_grant_target,
};

/// Shared state cloned into every grants-route handler. The `cache` field is
/// `Option<PermissionsCache>` because YAML-only installs (no state DB pool)
/// run without a resolver cache — invalidation is then a no-op.
#[derive(Clone)]
pub struct GrantsState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
    pub cache: Option<PermissionsCache>,
}

impl std::fmt::Debug for GrantsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantsState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .field("cache", &self.cache.as_ref().map(|_| "<PermissionsCache>"))
            .finish()
    }
}

pub async fn create(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<CreateGrantRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AdminError> {
    let Json(body) = body.map_err(|_| invalid_body(&actor.request_id))?;
    let target = parse_grant_target(&body, &actor.request_id)?;
    let action = parse_action(&body.action, &actor.request_id)?;
    let constraints = constraints_to_json(&body.constraints);

    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let grant = tx_create_grant(&mut tx, body.user_id, target, action, constraints)
        .await
        .map_err(|err| map_create_grant_error(err, &actor.request_id))?;

    // Resolve the user_sub through the tx so the cache hook below can see
    // the same DB state the audit row records.
    let user_sub = tx_user_sub_for_id(&mut tx, grant.user_id)
        .await
        .map_err(|err| internal("user_sub_for_id", err, &actor.request_id))?;

    // Upsert the actor's own row in the same tx as the audit write (atomicity).
    let actor_id = tx_upsert_actor(&mut tx, &actor.sub, &actor.email, &actor.groups)
        .await
        .map_err(|err| internal("upsert_actor", err, &actor.request_id))?;

    let audit_row = PermissionsAuditRow {
        actor_id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Create,
        target_type: PermissionsAuditTargetType::Grant,
        target_id: grant.id,
        before: None,
        after: Some(grant_payload(&grant)),
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

    invalidate_cache(&state.cache, user_sub.as_deref());

    Ok((StatusCode::CREATED, Json(GrantResponse::from(grant))))
}

pub async fn list(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    query: Result<Query<ListGrantsQuery>, QueryRejection>,
) -> Result<Json<Vec<GrantResponse>>, AdminError> {
    let Query(query) = query.map_err(|_| invalid_query(&actor.request_id))?;
    let grants = state
        .repo
        .list_grants(query.user_id, query.database_id)
        .await
        .map_err(|err| internal("list_grants", err, &actor.request_id))?;
    Ok(Json(grants.into_iter().map(GrantResponse::from).collect()))
}

pub async fn get_one(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<GrantResponse>, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let grant = state
        .repo
        .get_grant(id)
        .await
        .map_err(|err| internal("get_grant", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;
    Ok(Json(GrantResponse::from(grant)))
}

pub async fn patch(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<UpdateGrantRequest>, JsonRejection>,
) -> Result<Json<GrantResponse>, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let Json(body) = body.map_err(|_| invalid_body(&actor.request_id))?;
    if body.action.is_none() && body.constraints.is_none() {
        return Err(
            AdminError::invalid("PATCH body must set at least one of action, constraints")
                .with_request_id(&actor.request_id),
        );
    }
    let action = match body.action.as_deref() {
        Some(a) => Some(parse_action(a, &actor.request_id)?),
        None => None,
    };
    let constraints = body.constraints.as_ref().map(constraints_to_json);

    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let before = tx_get_grant_by_id(&mut tx, id)
        .await
        .map_err(|err| internal("get_grant", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let after = tx_update_grant(&mut tx, id, action, constraints)
        .await
        .map_err(|err| internal("update_grant", err, &actor.request_id))?
        // Race: someone revoked the grant between our read and our write.
        // Surface as 404 — the PATCH didn't apply.
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let user_sub = tx_user_sub_for_id(&mut tx, after.user_id)
        .await
        .map_err(|err| internal("user_sub_for_id", err, &actor.request_id))?;

    // Upsert the actor's own row in the same tx as the audit write (atomicity).
    let actor_id = tx_upsert_actor(&mut tx, &actor.sub, &actor.email, &actor.groups)
        .await
        .map_err(|err| internal("upsert_actor", err, &actor.request_id))?;

    let audit_row = PermissionsAuditRow {
        actor_id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Update,
        target_type: PermissionsAuditTargetType::Grant,
        target_id: after.id,
        before: Some(grant_payload(&before)),
        after: Some(grant_payload(&after)),
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

    invalidate_cache(&state.cache, user_sub.as_deref());

    Ok(Json(GrantResponse::from(after)))
}

pub async fn delete(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let before = tx_get_grant_by_id(&mut tx, id)
        .await
        .map_err(|err| internal("get_grant", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let revoked = tx_revoke_grant(&mut tx, id)
        .await
        .map_err(|err| internal("revoke_grant", err, &actor.request_id))?;
    if !revoked {
        return Err(AdminError::not_found().with_request_id(&actor.request_id));
    }

    let user_sub = tx_user_sub_for_id(&mut tx, before.user_id)
        .await
        .map_err(|err| internal("user_sub_for_id", err, &actor.request_id))?;

    // Upsert the actor's own row in the same tx as the audit write (atomicity).
    let actor_id = tx_upsert_actor(&mut tx, &actor.sub, &actor.email, &actor.groups)
        .await
        .map_err(|err| internal("upsert_actor", err, &actor.request_id))?;

    let audit_row = PermissionsAuditRow {
        actor_id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Delete,
        target_type: PermissionsAuditTargetType::Grant,
        target_id: id,
        before: Some(grant_payload(&before)),
        after: None,
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

    invalidate_cache(&state.cache, user_sub.as_deref());

    Ok(StatusCode::NO_CONTENT)
}

/// Fire-and-forget cache invalidation. Runs AFTER the tx commits so a
/// concurrent reader that re-warms during the gap sees the post-commit
/// state. A pre-commit invalidation would let the reader re-warm with the
/// stale grant, which is worse. The TTL (default 60s) is the safety net if
/// `cache` is `None` or the user_sub lookup returned `None`.
///
/// Detached via `tokio::spawn` so a client disconnect between the revision
/// bump and the entry removal cannot leave the stale entry live until TTL:
/// [`PermissionsCache::invalidate`] takes a write lock, and awaiting it on
/// the request task means cancellation drops the future mid-invalidate.
/// The spawned task owns its inputs and runs to completion regardless.
fn invalidate_cache(cache: &Option<PermissionsCache>, user_sub: Option<&str>) {
    if let (Some(cache), Some(sub)) = (cache.as_ref(), user_sub) {
        let cache = cache.clone();
        let sub = sub.to_string();
        tokio::spawn(async move {
            cache.invalidate(&sub).await;
        });
    }
}
