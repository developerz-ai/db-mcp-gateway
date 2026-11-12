//! CRUD handler functions for `/admin/v1/databases`.

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::audit::permissions::{PermissionsAuditAction as Action, PermissionsAuditTargetType};
use crate::state::permissions::PermissionsChange;
use crate::state::permissions::pg::{databases, grants};

use super::super::audited_tx::AuditedTx;
use super::super::error::AdminError;
use super::super::middleware::AdminActor;
use super::super::page_query::{PageQuery, invalid_query};
use super::super::payload::{database_payload, grant_payload};
use super::super::validation::{
    check_unchanged, internal, invalid_body, invalid_id, not_found, routing_name, store_error,
};
use super::validation::{map_duplicate_database_error, parse_db_type};
use super::{CreateDatabaseRequest, DatabaseResponse, DatabasesState, UpdateDatabaseRequest};

const DATABASE: PermissionsAuditTargetType = PermissionsAuditTargetType::Database;

pub async fn create(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<CreateDatabaseRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AdminError> {
    let rid = actor.request_id.as_str();
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    let server = routing_name(&body.server, "server", rid)?;
    let db_name = routing_name(&body.db_name, "db_name", rid)?;
    let db_type = parse_db_type(&body.db_type, rid)?;

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let database = databases::tx_create_database(atx.tx(), &server, &db_name, db_type)
        .await
        .map_err(|err| {
            map_duplicate_database_error(err, "create_database", &server, &db_name, rid)
        })?;
    let after = Some(database_payload(&database));
    atx.audit(Action::Create, DATABASE, database.id, None, after)
        .await?;
    atx.commit(&state.cache, None).await?;
    Ok((StatusCode::CREATED, Json(DatabaseResponse::from(database))))
}

pub async fn list(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    page: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Json<Vec<DatabaseResponse>>, AdminError> {
    let Query(page) = page.map_err(|_| invalid_query(&actor.request_id))?;
    let databases = state
        .repo
        .list_databases(page.to_page())
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
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("database", rid))?;
    let database = state
        .repo
        .get_database(id)
        .await
        .map_err(|err| internal("get_database", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    Ok(Json(DatabaseResponse::from(database)))
}

pub async fn patch(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<UpdateDatabaseRequest>, JsonRejection>,
) -> Result<Json<DatabaseResponse>, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("database", rid))?;
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    if body.server.is_none() && body.db_name.is_none() && body.db_type.is_none() {
        return Err(AdminError::invalid(
            "PATCH body must set at least one of server, db_name, db_type",
        )
        .with_request_id(rid));
    }
    let server = body
        .server
        .as_deref()
        .map(|s| routing_name(s, "server", rid))
        .transpose()?;
    let db_name = body
        .db_name
        .as_deref()
        .map(|d| routing_name(d, "db_name", rid))
        .transpose()?;
    let db_type = body
        .db_type
        .as_deref()
        .map(|t| parse_db_type(t, rid))
        .transpose()?;

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let before = databases::tx_lock_database(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_database", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    check_unchanged(body.expected_updated_at, before.updated_at, rid)?;
    let after =
        databases::tx_update_database(atx.tx(), id, server.as_deref(), db_name.as_deref(), db_type)
            .await
            .map_err(|err| {
                // The pair that collided is whichever field the body set, falling
                // back to the row's current value.
                let server = server.as_deref().unwrap_or(&before.server);
                let db_name = db_name.as_deref().unwrap_or(&before.db_name);
                map_duplicate_database_error(err, "update_database", server, db_name, rid)
            })?
            .ok_or_else(|| not_found(rid))?;
    let (before_json, after_json) = (database_payload(&before), database_payload(&after));
    atx.audit(
        Action::Update,
        DATABASE,
        id,
        Some(before_json),
        Some(after_json),
    )
    .await?;
    atx.commit(&state.cache, Some(PermissionsChange::All))
        .await?;
    Ok(Json(DatabaseResponse::from(after)))
}

/// Soft-delete the database and revoke every specific grant on it, in one
/// transaction with one audit row per revoked grant plus the database's.
/// Wildcard grants name the server, not this row, and stay.
pub async fn delete(
    State(state): State<DatabasesState>,
    Extension(actor): Extension<AdminActor>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, AdminError> {
    let rid = actor.request_id.as_str();
    let Path(id) = id.map_err(|_| invalid_id("database", rid))?;

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let before = databases::tx_lock_database(atx.tx(), id)
        .await
        .map_err(|err| store_error("lock_database", err, rid))?
        .ok_or_else(|| not_found(rid))?;
    let revoked = grants::tx_revoke_grants_for_database(atx.tx(), id)
        .await
        .map_err(|err| store_error("revoke_database_grants", err, rid))?;
    if !databases::tx_soft_delete_database(atx.tx(), id)
        .await
        .map_err(|err| store_error("soft_delete_database", err, rid))?
    {
        return Err(not_found(rid));
    }
    for grant in &revoked {
        let target = PermissionsAuditTargetType::Grant;
        let before_json = Some(grant_payload(grant));
        atx.audit(Action::Delete, target, grant.id, before_json, None)
            .await?;
    }
    let before_json = Some(database_payload(&before));
    atx.audit(Action::Delete, DATABASE, id, before_json, None)
        .await?;
    atx.commit(&state.cache, Some(PermissionsChange::All))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
