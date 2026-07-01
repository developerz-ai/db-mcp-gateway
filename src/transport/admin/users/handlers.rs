//! CRUD handler functions for `/admin/v1/users`.

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::permissions::{
    self, PermissionsAuditAction, PermissionsAuditRow, PermissionsAuditTargetType,
};

use super::super::error::AdminError;
use super::super::middleware::{AdminActor, tx_upsert_actor};
use super::tx::{
    tx_get_user_by_id, tx_get_user_by_sub, tx_soft_delete_user, tx_update_user, tx_upsert_user,
};
use super::{CreateUserRequest, UpdateUserRequest, UserResponse, UsersState};
use super::{internal, invalid_body, invalid_id, trimmed_non_empty, user_payload};

pub async fn create(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    // Fallible extractor: rejection (malformed/non-JSON body) returns the
    // stable admin error JSON with a `request_id`, not Axum's default 400/422
    // body that lacks our `code`/`request_id` contract.
    body: Result<Json<CreateUserRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AdminError> {
    let Json(body) = body.map_err(|_| invalid_body(&actor.request_id))?;
    let user_sub = trimmed_non_empty(&body.user_sub, "user_sub", &actor.request_id)?;
    let user_email = trimmed_non_empty(&body.user_email, "user_email", &actor.request_id)?;

    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    // Read + write share the SAME transaction so the audit write (below) can
    // roll back both halves atomically. Hitting the pool directly for the
    // data write — as an early draft of this handler did — leaves the data
    // committed even if the audit step fails. CLAUDE.md non-negotiable #4.
    let before = tx_get_user_by_sub(&mut tx, &user_sub)
        .await
        .map_err(|err| internal("get_user_by_sub", err, &actor.request_id))?;

    let user = tx_upsert_user(&mut tx, &user_sub, &user_email, &body.groups)
        .await
        .map_err(|err| internal("upsert_user", err, &actor.request_id))?;

    // Upsert the actor's own row in the same tx as the audit write (atomicity).
    // Guard: if the actor is mutating their own row, skip the upsert — the
    // `tx_upsert_user` call above already wrote the correct state for that sub,
    // and running `tx_upsert_actor` would overwrite it with the session snapshot
    // (stale email/groups), clobbering the just-applied mutation.
    let actor_id = if actor.sub == user_sub {
        user.id
    } else {
        tx_upsert_actor(&mut tx, &actor.sub, &actor.email, &actor.groups)
            .await
            .map_err(|err| internal("upsert_actor", err, &actor.request_id))?
    };

    let action = if before.is_some() {
        PermissionsAuditAction::Update
    } else {
        PermissionsAuditAction::Create
    };
    let audit_row = PermissionsAuditRow {
        actor_id,
        actor_email: actor.email.clone(),
        action,
        target_type: PermissionsAuditTargetType::User,
        target_id: user.id,
        before: before.as_ref().map(user_payload),
        after: Some(user_payload(&user)),
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

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
) -> Result<Json<Vec<UserResponse>>, AdminError> {
    let users = state
        .repo
        .list_users()
        .await
        .map_err(|err| internal("list_users", err, &actor.request_id))?;
    Ok(Json(users.into_iter().map(UserResponse::from).collect()))
}

pub async fn get_one(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<UserResponse>, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let user = state
        .repo
        .get_user(id)
        .await
        .map_err(|err| internal("get_user", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;
    Ok(Json(UserResponse::from(user)))
}

pub async fn patch(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<UpdateUserRequest>, JsonRejection>,
) -> Result<Json<UserResponse>, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let Json(body) = body.map_err(|_| invalid_body(&actor.request_id))?;
    if body.user_email.is_none() && body.groups.is_none() {
        return Err(
            AdminError::invalid("PATCH body must set at least one of user_email, groups")
                .with_request_id(&actor.request_id),
        );
    }
    let user_email = match body.user_email.as_deref() {
        Some(e) => Some(trimmed_non_empty(e, "user_email", &actor.request_id)?),
        None => None,
    };

    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let before = tx_get_user_by_id(&mut tx, id)
        .await
        .map_err(|err| internal("get_user", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let after = tx_update_user(&mut tx, id, user_email.as_deref(), body.groups.as_deref())
        .await
        .map_err(|err| internal("update_user", err, &actor.request_id))?
        // Race: someone soft-deleted the user between our read and our write.
        // Surface as 404 — the PATCH didn't apply.
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    // Upsert the actor's own row in the same tx as the audit write (atomicity).
    // Guard: if the actor is patching their own row, skip the upsert to avoid
    // overwriting the freshly-patched state with the session snapshot.
    let actor_id = if actor.sub == before.user_sub {
        after.id
    } else {
        tx_upsert_actor(&mut tx, &actor.sub, &actor.email, &actor.groups)
            .await
            .map_err(|err| internal("upsert_actor", err, &actor.request_id))?
    };

    let audit_row = PermissionsAuditRow {
        actor_id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Update,
        target_type: PermissionsAuditTargetType::User,
        target_id: after.id,
        before: Some(user_payload(&before)),
        after: Some(user_payload(&after)),
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

    Ok(Json(UserResponse::from(after)))
}

pub async fn delete(
    State(state): State<UsersState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let before = tx_get_user_by_id(&mut tx, id)
        .await
        .map_err(|err| internal("get_user", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let deleted = tx_soft_delete_user(&mut tx, id)
        .await
        .map_err(|err| internal("soft_delete_user", err, &actor.request_id))?;
    if !deleted {
        return Err(AdminError::not_found().with_request_id(&actor.request_id));
    }

    // Upsert the actor's own row in the same tx as the audit write (atomicity).
    // Guard: if the actor is deleting their own row, skip the upsert — the
    // DELETE already soft-deleted the row, and re-inserting via upsert would
    // create a new active row that immediately cancels the soft-delete.
    let actor_id = if actor.sub == before.user_sub {
        before.id
    } else {
        tx_upsert_actor(&mut tx, &actor.sub, &actor.email, &actor.groups)
            .await
            .map_err(|err| internal("upsert_actor", err, &actor.request_id))?
    };

    let audit_row = PermissionsAuditRow {
        actor_id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Delete,
        target_type: PermissionsAuditTargetType::User,
        target_id: id,
        before: Some(user_payload(&before)),
        after: None,
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;
    Ok(StatusCode::NO_CONTENT)
}
