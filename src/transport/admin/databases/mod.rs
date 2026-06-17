//! `/admin/v1/databases` handlers (#53).
//!
//! Register/manage the logical `(server, db_name, db_type)` records that
//! grants attach to. Same tx-wrapped data+audit write pattern as
//! [`super::users`]; the same CLAUDE.md non-negotiable #4 contract.
//!
//! ## DSN never crosses this surface
//!
//! Per spec 12 §"What the API never returns" and CLAUDE.md non-negotiable #1:
//! connection strings, role passwords, and role secrets stay in YAML/secrets.
//! This module enforces that on **both** directions:
//!
//! - **Out:** `permissions_databases` has no credential columns (migration
//!   `0004_permissions.sql`), so the response struct literally cannot leak one.
//! - **In:** request DTOs declare `#[serde(deny_unknown_fields)]`. A POST/PATCH
//!   body carrying a `connection_string`, `dsn`, `password`, `role`, or any
//!   other unknown field is rejected at the parse layer with `400
//!   invalid_request` — the handler never sees the field, so it can't accidentally
//!   log or echo it. This is the headline acceptance criterion from #53.
//!
//! ## File layout
//!
//! Split across submodules to keep each file under the CLAUDE.md 300-LOC
//! ceiling: [`dto`] for request/response shapes, [`sql`] for the tx-scoped
//! SQL helpers, [`validation`] for input parsing + error mapping. This file
//! owns only the route handlers and the audit payload builder.

mod dto;
mod sql;
mod validation;

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value as JsonValue, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::audit::permissions::{
    self, PermissionsAuditAction, PermissionsAuditRow, PermissionsAuditTargetType,
};
use crate::state::permissions::{PermissionsDatabase, PermissionsRepo};

use super::error::AdminError;
use super::middleware::AdminActor;

pub use dto::{CreateDatabaseRequest, DatabaseResponse, UpdateDatabaseRequest};

use sql::{tx_create_database, tx_get_database_by_id, tx_soft_delete_database, tx_update_database};
use validation::{internal, invalid_body, invalid_id, parse_db_type, trimmed_non_empty};

/// Shared state cloned into every databases-route handler.
#[derive(Clone)]
pub struct DatabasesState {
    pub repo: Arc<dyn PermissionsRepo>,
    pub state_db: PgPool,
}

impl std::fmt::Debug for DatabasesState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabasesState")
            .field("repo", &"<Arc<dyn PermissionsRepo>>")
            .field("state_db", &"<PgPool>")
            .finish()
    }
}

pub async fn create(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<CreateDatabaseRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AdminError> {
    let Json(body) = body.map_err(|_| invalid_body(&actor.request_id))?;
    let server = trimmed_non_empty(&body.server, "server", &actor.request_id)?;
    let db_name = trimmed_non_empty(&body.db_name, "db_name", &actor.request_id)?;
    let db_type = parse_db_type(&body.db_type, &actor.request_id)?;

    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let database = tx_create_database(&mut tx, &server, &db_name, db_type)
        .await
        .map_err(|err| internal("create_database", err, &actor.request_id))?;

    let audit_row = PermissionsAuditRow {
        actor_id: actor.id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Create,
        target_type: PermissionsAuditTargetType::Database,
        target_id: database.id,
        before: None,
        after: Some(database_payload(&database)),
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

    Ok((StatusCode::CREATED, Json(DatabaseResponse::from(database))))
}

pub async fn list(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
) -> Result<Json<Vec<DatabaseResponse>>, AdminError> {
    let databases = state
        .repo
        .list_databases()
        .await
        .map_err(|err| internal("list_databases", err, &actor.request_id))?;
    Ok(Json(
        databases.into_iter().map(DatabaseResponse::from).collect(),
    ))
}

pub async fn get_one(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<DatabaseResponse>, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let database = state
        .repo
        .get_database(id)
        .await
        .map_err(|err| internal("get_database", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;
    Ok(Json(DatabaseResponse::from(database)))
}

pub async fn patch(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<UpdateDatabaseRequest>, JsonRejection>,
) -> Result<Json<DatabaseResponse>, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let Json(body) = body.map_err(|_| invalid_body(&actor.request_id))?;
    if body.server.is_none() && body.db_name.is_none() && body.db_type.is_none() {
        return Err(AdminError::invalid(
            "PATCH body must set at least one of server, db_name, db_type",
        )
        .with_request_id(&actor.request_id));
    }
    let server = match body.server.as_deref() {
        Some(s) => Some(trimmed_non_empty(s, "server", &actor.request_id)?),
        None => None,
    };
    let db_name = match body.db_name.as_deref() {
        Some(d) => Some(trimmed_non_empty(d, "db_name", &actor.request_id)?),
        None => None,
    };
    let db_type = match body.db_type.as_deref() {
        Some(t) => Some(parse_db_type(t, &actor.request_id)?),
        None => None,
    };

    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let before = tx_get_database_by_id(&mut tx, id)
        .await
        .map_err(|err| internal("get_database", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let after = tx_update_database(&mut tx, id, server.as_deref(), db_name.as_deref(), db_type)
        .await
        .map_err(|err| internal("update_database", err, &actor.request_id))?
        // Race: someone soft-deleted between our read and our write.
        // Surface as 404 — the PATCH didn't apply.
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let audit_row = PermissionsAuditRow {
        actor_id: actor.id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Update,
        target_type: PermissionsAuditTargetType::Database,
        target_id: after.id,
        before: Some(database_payload(&before)),
        after: Some(database_payload(&after)),
        request_id: actor.request_id.clone(),
    };
    permissions::log(&mut *tx, &audit_row)
        .await
        .map_err(|err| internal("audit log", err, &actor.request_id))?;

    tx.commit()
        .await
        .map_err(|err| internal("commit tx", err, &actor.request_id))?;

    Ok(Json(DatabaseResponse::from(after)))
}

pub async fn delete(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, AdminError> {
    let Path(id) = id.map_err(|_| invalid_id(&actor.request_id))?;
    let mut tx = state
        .state_db
        .begin()
        .await
        .map_err(|err| internal("begin tx", err, &actor.request_id))?;

    let before = tx_get_database_by_id(&mut tx, id)
        .await
        .map_err(|err| internal("get_database", err, &actor.request_id))?
        .ok_or_else(|| AdminError::not_found().with_request_id(&actor.request_id))?;

    let deleted = tx_soft_delete_database(&mut tx, id)
        .await
        .map_err(|err| internal("soft_delete_database", err, &actor.request_id))?;
    if !deleted {
        return Err(AdminError::not_found().with_request_id(&actor.request_id));
    }

    let audit_row = PermissionsAuditRow {
        actor_id: actor.id,
        actor_email: actor.email.clone(),
        action: PermissionsAuditAction::Delete,
        target_type: PermissionsAuditTargetType::Database,
        target_id: id,
        before: Some(database_payload(&before)),
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

fn database_payload(d: &PermissionsDatabase) -> JsonValue {
    json!({
        "id": d.id,
        "server": d.server,
        "db_name": d.db_name,
        "db_type": d.db_type.as_db_str(),
        "created_at": d.created_at,
        "updated_at": d.updated_at,
    })
}
