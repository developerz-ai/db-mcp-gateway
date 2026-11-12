//! CRUD handler functions for `/admin/v1/grants`.

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::permissions::{PermissionsAuditAction as Action, PermissionsAuditTargetType};
use crate::config::Constraints;
use crate::state::permissions::PermissionsChange;
use crate::state::permissions::pg::{grants, users};

use super::super::audited_tx::AuditedTx;
use super::super::error::AdminError;
use super::super::middleware::AdminActor;
use super::super::page_query::invalid_query;
use super::super::payload::grant_payload;
use super::super::validation::{
    check_unchanged, internal, invalid_body, invalid_id, not_found, store_error,
};
use super::validation::{
    constraints_to_json, map_create_grant_error, parse_action, parse_grant_target, positive_bounds,
    positive_patch_bounds,
};
use super::{CreateGrantRequest, GrantResponse, GrantsState, ListGrantsQuery, UpdateGrantRequest};

const GRANT: PermissionsAuditTargetType = PermissionsAuditTargetType::Grant;

pub async fn create(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<CreateGrantRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AdminError> {
    let rid = actor.request_id.as_str();
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    let target = parse_grant_target(&body, &state.known_servers, rid)?;
    let action = parse_action(&body.action, rid)?;
    positive_bounds(&body.constraints, rid)?;
    let constraints = constraints_to_json(&body.constraints);

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let grant = grants::tx_create_grant(atx.tx(), body.user_id, &target, action, &constraints)
        .await
        .map_err(|err| map_create_grant_error(err, rid))?
        .ok_or_else(|| {
            AdminError::invalid("invalid grant reference: user or database does not exist")
                .with_request_id(rid)
        })?;
    let change = change_for_user(&mut atx, grant.user_id).await?;
    atx.audit(
        Action::Create,
        GRANT,
        grant.id,
        None,
        Some(grant_payload(&grant)),
    )
    .await?;
    atx.commit(&state.cache, Some(change)).await?;
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
        .list_grants(query.user_id, query.database_id, query.to_page())
        .await
        .map_err(|err| internal("list_grants", err, &actor.request_id))?;
    Ok(Json(grants.into_iter().map(GrantResponse::from).collect()))
}

pub async fn get_one(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<GrantResponse>, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("grant", rid))?;
    let grant = state
        .repo
        .get_grant(id)
        .await
        .map_err(|err| internal("get_grant", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    Ok(Json(GrantResponse::from(grant)))
}

/// Per-key merge onto the locked row: keys the body omits keep their stored
/// value, so concurrent PATCHes compose instead of clobbering, and the audit
/// chain stays continuous (`after[n] == before[n+1]`).
pub async fn patch(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<UpdateGrantRequest>, JsonRejection>,
) -> Result<Json<GrantResponse>, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("grant", rid))?;
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    let patch = body.constraints.unwrap_or_default();
    if body.action.is_none() && patch.is_empty() {
        return Err(
            AdminError::invalid("PATCH body must set at least one of action, constraints")
                .with_request_id(rid),
        );
    }
    let action = body
        .action
        .as_deref()
        .map(|a| parse_action(a, rid))
        .transpose()?;
    positive_patch_bounds(&patch, rid)?;

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let before = grants::tx_lock_grant(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_grant", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    check_unchanged(body.expected_updated_at, before.updated_at, rid)?;
    // A stored object the schema can't read is refused, not overwritten:
    // the merge must start from what the resolver enforces today.
    let current: Constraints = serde_json::from_value(before.constraints.clone())
        .map_err(|err| internal("decode constraints", err, rid))?;
    let merged = constraints_to_json(&patch.apply(&current));
    let after = grants::tx_update_grant(atx.tx(), id, action, &merged)
        .await
        .map_err(|err| store_error("update_grant", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    let change = change_for_user(&mut atx, after.user_id).await?;
    let (before_json, after_json) = (grant_payload(&before), grant_payload(&after));
    atx.audit(
        Action::Update,
        GRANT,
        id,
        Some(before_json),
        Some(after_json),
    )
    .await?;
    atx.commit(&state.cache, Some(change)).await?;
    Ok(Json(GrantResponse::from(after)))
}

pub async fn delete(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("grant", rid))?;

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let before = grants::tx_lock_grant(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_grant", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    if !grants::tx_revoke_grant(atx.tx(), id)
        .await
        .map_err(|err| store_error("revoke_grant", err, rid))?
    {
        return Err(not_found(rid));
    }
    let change = change_for_user(&mut atx, before.user_id).await?;
    atx.audit(
        Action::Delete,
        GRANT,
        id,
        Some(grant_payload(&before)),
        None,
    )
    .await?;
    atx.commit(&state.cache, Some(change)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The cache key a change to `user_id`'s grants invalidates. A grant whose
/// user row vanished cannot be keyed, so flush everything.
async fn change_for_user(
    atx: &mut AuditedTx<'_>,
    user_id: Uuid,
) -> Result<PermissionsChange, AdminError> {
    let rid = atx.request_id();
    let sub = users::tx_user_sub(atx.tx(), user_id)
        .await
        .map_err(|err| store_error("user_sub", err, rid))?;
    Ok(sub.map_or(PermissionsChange::All, PermissionsChange::User))
}
