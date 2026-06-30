//! `/admin/v1/users` handlers (#52).
//!
//! Every write opens a state-DB transaction, calls the repo, writes the
//! `permissions_audit` row through the same transaction, then commits. Audit
//! failure → transaction rolls back → handler returns 5xx. CLAUDE.md
//! non-negotiable #4 (synchronous audit) honored end-to-end.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::audit::permissions::{
    self, PermissionsAuditAction, PermissionsAuditRow, PermissionsAuditTargetType,
};
use crate::state::permissions::{PermissionsRepo, PermissionsUser, RepoError};

use super::error::AdminError;
use super::middleware::{AdminActor, tx_upsert_actor};

/// Shared state cloned into every users-route handler.
#[derive(Clone)]
pub struct UsersState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
}

impl std::fmt::Debug for UsersState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsersState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .finish()
    }
}

/// Public response shape. Carries no credentials — `permissions_users` rows
/// never hold any — but kept as a dedicated DTO so adding fields to the
/// storage struct doesn't accidentally widen the admin surface.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub user_sub: String,
    pub user_email: String,
    pub groups: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PermissionsUser> for UserResponse {
    fn from(u: PermissionsUser) -> Self {
        Self {
            id: u.id,
            user_sub: u.user_sub,
            user_email: u.user_email,
            groups: u.groups,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub user_sub: String,
    pub user_email: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub groups: Option<Vec<String>>,
}

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

/// Map a `JsonRejection` (malformed/missing body, bad content-type) onto the
/// stable admin-error envelope so clients see `invalid_request` + `request_id`
/// instead of Axum's default 400/422.
fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

/// Map a `PathRejection` (malformed UUID in `:id`) onto the stable admin-error
/// envelope.
fn invalid_id(request_id: &str) -> AdminError {
    AdminError::invalid("invalid user id").with_request_id(request_id)
}

fn trimmed_non_empty(value: &str, field: &str, request_id: &str) -> Result<String, AdminError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(AdminError::invalid(format!("{field} must be non-empty")).with_request_id(request_id))
    } else {
        Ok(trimmed.to_string())
    }
}

fn user_payload(u: &PermissionsUser) -> JsonValue {
    json!({
        "id": u.id,
        "user_sub": u.user_sub,
        "user_email": u.user_email,
        "groups": u.groups,
        "created_at": u.created_at,
        "updated_at": u.updated_at,
    })
}

// ----- Transactional SQL helpers -----
//
// The admin handlers must read AND write through the same `tx` as the audit
// log, so an audit-write failure rolls back the data change. The
// [`PermissionsRepo`] trait is pool-backed by design (resolver hot path
// doesn't need transactions), so admin writes inline the SQL here instead of
// adding a Generic-Executor variant to the trait.
//
// These helpers mirror `state::permissions::pg::PgPermissionsRepo` 1:1 —
// only the executor is different.

async fn tx_get_user_by_sub(
    tx: &mut Transaction<'_, Postgres>,
    user_sub: &str,
) -> Result<Option<PermissionsUser>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE user_sub = $1 AND deleted_at IS NULL",
    )
    .bind(user_sub)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| user_from_row_admin(&r)).transpose()
}

async fn tx_get_user_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsUser>, RepoError> {
    let row = sqlx::query(
        "SELECT id, user_sub, user_email, groups, created_at, updated_at, deleted_at \
         FROM permissions_users \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| user_from_row_admin(&r)).transpose()
}

async fn tx_upsert_user(
    tx: &mut Transaction<'_, Postgres>,
    user_sub: &str,
    user_email: &str,
    groups: &[String],
) -> Result<PermissionsUser, RepoError> {
    let groups_json = serde_json::to_value(groups).map_err(RepoError::EncodeGroups)?;
    let row = sqlx::query(
        "INSERT INTO permissions_users (user_sub, user_email, groups) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (user_sub) WHERE deleted_at IS NULL \
         DO UPDATE SET user_email = EXCLUDED.user_email, \
                       groups = EXCLUDED.groups, \
                       updated_at = now() \
         RETURNING id, user_sub, user_email, groups, created_at, updated_at, deleted_at",
    )
    .bind(user_sub)
    .bind(user_email)
    .bind(&groups_json)
    .fetch_one(&mut **tx)
    .await?;
    user_from_row_admin(&row)
}

async fn tx_update_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user_email: Option<&str>,
    groups: Option<&[String]>,
) -> Result<Option<PermissionsUser>, RepoError> {
    let groups_json = match groups {
        Some(g) => Some(serde_json::to_value(g).map_err(RepoError::EncodeGroups)?),
        None => None,
    };
    let row = sqlx::query(
        "UPDATE permissions_users \
         SET user_email = COALESCE($2, user_email), \
             groups = COALESCE($3, groups), \
             updated_at = now() \
         WHERE id = $1 AND deleted_at IS NULL \
         RETURNING id, user_sub, user_email, groups, created_at, updated_at, deleted_at",
    )
    .bind(id)
    .bind(user_email)
    .bind(groups_json)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| user_from_row_admin(&r)).transpose()
}

async fn tx_soft_delete_user(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_users SET deleted_at = now() \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

fn user_from_row_admin(row: &sqlx::postgres::PgRow) -> Result<PermissionsUser, RepoError> {
    let groups_json: JsonValue = row.try_get("groups")?;
    let groups: Vec<String> =
        serde_json::from_value(groups_json).map_err(RepoError::DecodeGroups)?;
    Ok(PermissionsUser {
        id: row.try_get("id")?,
        user_sub: row.try_get("user_sub")?,
        user_email: row.try_get("user_email")?,
        groups,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        deleted_at: row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?,
    })
}

/// Build an `internal` admin error and trace the failure.
///
/// We log only `stage`, `error_type`, and `request_id` — never `%err`. A
/// PostgreSQL error's `Display` impl embeds `detail`/`constraint` text, which
/// on `permissions_users` carries user emails and group names. CLAUDE.md
/// non-negotiable #1 forbids leaking that into logs.
fn internal<E>(stage: &'static str, _err: E, request_id: &str) -> AdminError {
    let error_type = std::any::type_name::<E>();
    tracing::error!(
        stage,
        error_type,
        %request_id,
        "admin users endpoint failed"
    );
    AdminError::internal().with_request_id(request_id)
}
