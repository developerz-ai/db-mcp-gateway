//! CRUD handler functions for `/admin/v1/users`.
//!
//! Lock order: the actor row, then the target row — except when the target
//! *is* the actor, where the one row plays both parts. `user_sub` is
//! immutable, so an unlocked read of it picks the branch before any lock.

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::permissions::{PermissionsAuditAction as Action, PermissionsAuditTargetType};
use crate::state::permissions::PermissionsChange;
use crate::state::permissions::pg::{grants, users};

use super::super::audited_tx::AuditedTx;
use super::super::error::AdminError;
use super::super::middleware::AdminActor;
use super::super::page_query::{PageQuery, invalid_query};
use super::super::payload::{grant_payload, user_payload};
use super::super::validation::{
    check_unchanged, internal, invalid_body, invalid_id, not_found, store_error, trimmed_non_empty,
};
use super::{CreateUserRequest, UpdateUserRequest, UserResponse, UsersState};
use super::{sso_subject, validate_groups};

const USER: PermissionsAuditTargetType = PermissionsAuditTargetType::User;

pub async fn create(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<CreateUserRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AdminError> {
    let rid = actor.request_id.as_str();
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    let user_sub = sso_subject(&body.user_sub, rid)?;
    let user_email = trimmed_non_empty(&body.user_email, "user_email", rid)?;
    let groups = validate_groups(&body.groups, rid)?;

    let mut atx = AuditedTx::begin(&state.state_db, &actor).await?;
    let is_self = actor.sub == user_sub;
    if !is_self {
        atx.lock_actor().await?;
    }
    let before = users::tx_lock_user_by_sub(atx.tx(), &user_sub)
        .await
        .map_err(|err| store_error("lock_user", err, rid))?;
    let user = users::tx_upsert_user(atx.tx(), &user_sub, &user_email, &groups)
        .await
        .map_err(|err| store_error("upsert_user", err, rid))?;
    if is_self {
        atx.actor_is(user.id);
    }
    let action = if before.is_some() {
        Action::Update
    } else {
        Action::Create
    };
    let before_json = before.as_ref().map(user_payload);
    atx.audit(
        action,
        USER,
        user.id,
        before_json,
        Some(user_payload(&user)),
    )
    .await?;
    // A re-POST of an existing subject can change its groups — and the
    // cached entry for that subject — so even an upsert invalidates.
    let change = PermissionsChange::User(user.user_sub.clone());
    atx.commit(&state.cache, Some(change)).await?;

    let status = if before.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(UserResponse::from(user))))
}

pub async fn list(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    page: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<Vec<UserResponse>>, AdminError> {
    let Query(page) = page.map_err(|_| invalid_query(&actor.request_id))?;
    let users = state
        .repo
        .list_users(page.to_page())
        .await
        .map_err(|err| internal("list_users", err, &actor.request_id))?;
    Ok(Json(users.into_iter().map(UserResponse::from).collect()))
}

pub async fn get_one(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<UserResponse>, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("user", rid))?;
    let user = state
        .repo
        .get_user(id)
        .await
        .map_err(|err| internal("get_user", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    Ok(Json(UserResponse::from(user)))
}

pub async fn patch(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Result<Json<UserResponse>, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("user", rid))?;
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    if body.user_email.is_none() && body.groups.is_none() {
        return Err(
            AdminError::invalid("PATCH body must set at least one of user_email, groups")
                .with_request_id(rid),
        );
    }
    let user_email = body
        .user_email
        .as_deref()
        .map(|e| trimmed_non_empty(e, "user_email", rid))
        .transpose()?;
    let groups = body
        .groups
        .as_deref()
        .map(|g| validate_groups(g, rid))
        .transpose()?;

    let mut atx = AuditedTx::begin(&state.state_db, &actor).await?;
    let is_self = lock_actor_unless_self(&mut atx, &actor, id).await?;
    let before = users::tx_lock_user(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_user", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    check_unchanged(body.expected_updated_at, before.updated_at, rid)?;
    let after = users::tx_update_user(atx.tx(), id, user_email.as_deref(), groups.as_deref())
        .await
        .map_err(|err| store_error("update_user", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    if is_self {
        atx.actor_is(after.id);
    }
    let (before_json, after_json) = (user_payload(&before), user_payload(&after));
    atx.audit(
        Action::Update,
        USER,
        id,
        Some(before_json),
        Some(after_json),
    )
    .await?;
    let change = PermissionsChange::User(after.user_sub.clone());
    atx.commit(&state.cache, Some(change)).await?;
    Ok(Json(UserResponse::from(after)))
}

/// Soft-delete the user and revoke every live grant it holds, in one
/// transaction with one audit row per revoked grant plus the user's.
pub async fn delete(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("user", rid))?;

    let mut atx = AuditedTx::begin(&state.state_db, &actor).await?;
    let is_self = lock_actor_unless_self(&mut atx, &actor, id).await?;
    let before = users::tx_lock_user(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_user", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    if is_self {
        atx.actor_is(before.id);
    }
    let revoked = grants::tx_revoke_grants_for_user(atx.tx(), id)
        .await
        .map_err(|err| store_error("revoke_user_grants", err, rid))?;
    if !users::tx_soft_delete_user(atx.tx(), id)
        .await
        .map_err(|err| store_error("soft_delete_user", err, rid))?
    {
        return Err(not_found(rid));
    }
    for grant in &revoked {
        let target = PermissionsAuditTargetType::Grant;
        let before_json = Some(grant_payload(grant));
        atx.audit(Action::Delete, target, grant.id, before_json, None)
            .await?;
    }
    atx.audit(Action::Delete, USER, id, Some(user_payload(&before)), None)
        .await?;
    let change = PermissionsChange::User(before.user_sub.clone());
    atx.commit(&state.cache, Some(change)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Pick the lock order for a mutation of user `id`: lock the actor row first
/// unless `id` is the actor's own row. Returns whether it is. A missing id
/// is a 404.
pub(super) async fn lock_actor_unless_self(
    atx: &mut AuditedTx<'_>,
    actor: &AdminActor,
    id: Uuid,
) -> Result<bool, AdminError> {
    let rid = actor.request_id.as_str();
    let sub = users::tx_user_sub(atx.tx(), id)
        .await
        .map_err(|err| store_error("user_sub", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    let is_self = sub == actor.sub;
    if !is_self {
        atx.lock_actor().await?;
    }
    Ok(is_self)
}
