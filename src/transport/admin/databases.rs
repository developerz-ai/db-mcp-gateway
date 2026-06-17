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
use crate::state::permissions::{DbType, PermissionsDatabase, PermissionsRepo, RepoError};

use super::error::AdminError;
use super::middleware::AdminActor;

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

/// Public response shape. The storage struct never carries credentials by
/// design (migration `0004_permissions.sql` has no DSN/role/password column),
/// so this DTO cannot leak one. Kept as a dedicated type so a future schema
/// change can't quietly widen the admin surface.
#[derive(Debug, Serialize)]
pub struct DatabaseResponse {
    pub id: Uuid,
    pub server: String,
    pub db_name: String,
    pub db_type: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PermissionsDatabase> for DatabaseResponse {
    fn from(d: PermissionsDatabase) -> Self {
        Self {
            id: d.id,
            server: d.server,
            db_name: d.db_name,
            db_type: d.db_type.as_db_str().to_string(),
            created_at: d.created_at,
            updated_at: d.updated_at,
        }
    }
}

/// `deny_unknown_fields` is the security primitive. Any extra field (`dsn`,
/// `connection_string`, `password`, `role`, …) → 400 at parse time. The
/// handler never sees the unknown field; it can't be logged or echoed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDatabaseRequest {
    pub server: String,
    pub db_name: String,
    pub db_type: String,
}

/// Partial-update DTO. Same `deny_unknown_fields` discipline as create.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDatabaseRequest {
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub db_name: Option<String>,
    #[serde(default)]
    pub db_type: Option<String>,
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

fn invalid_body(request_id: &str) -> AdminError {
    AdminError::invalid("invalid JSON body").with_request_id(request_id)
}

fn invalid_id(request_id: &str) -> AdminError {
    AdminError::invalid("invalid database id").with_request_id(request_id)
}

fn trimmed_non_empty(value: &str, field: &str, request_id: &str) -> Result<String, AdminError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(AdminError::invalid(format!("{field} must be non-empty")).with_request_id(request_id))
    } else {
        Ok(trimmed.to_string())
    }
}

/// Reject anything outside the `permissions_databases.db_type` CHECK (currently
/// `postgres` | `mysql`). `mongo` is intentionally rejected — spec 12
/// §"Storage backends" excludes mongo from the permissions store; it appears
/// only as a query target (#57–#58). Surfacing the rejection here keeps the
/// error code stable (`invalid_request`) instead of a 500 from the eventual
/// DB CHECK violation.
fn parse_db_type(value: &str, request_id: &str) -> Result<DbType, AdminError> {
    DbType::parse(value.trim()).map_err(|_| {
        AdminError::invalid(format!(
            "db_type `{value}` not supported (allowed: postgres, mysql)"
        ))
        .with_request_id(request_id)
    })
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

/// Same logging discipline as [`super::users::internal`]: we log `stage` +
/// `error_type` + `request_id` but NEVER the underlying error string. A sqlx
/// error's `Display` impl can quote constraint-violation detail that, on
/// `permissions_databases`, would include the offending `server`/`db_name`
/// values — and could in principle echo back content from a future column
/// we haven't anticipated. CLAUDE.md non-negotiable #1.
fn internal<E>(stage: &'static str, _err: E, request_id: &str) -> AdminError {
    let error_type = std::any::type_name::<E>();
    tracing::error!(
        stage,
        error_type,
        %request_id,
        "admin databases endpoint failed"
    );
    AdminError::internal().with_request_id(request_id)
}

// ----- Transactional SQL helpers -----
//
// Same rationale as [`super::users`]: the data write MUST share the tx with
// the audit log so an audit failure rolls back both. The [`PermissionsRepo`]
// trait stays pool-backed (resolver hot path doesn't need transactions); the
// admin handlers inline the SQL here.

async fn tx_create_database(
    tx: &mut Transaction<'_, Postgres>,
    server: &str,
    db_name: &str,
    db_type: DbType,
) -> Result<PermissionsDatabase, RepoError> {
    let row = sqlx::query(
        "INSERT INTO permissions_databases (server, db_name, db_type) \
         VALUES ($1, $2, $3) \
         RETURNING id, server, db_name, db_type, created_at, updated_at, deleted_at",
    )
    .bind(server)
    .bind(db_name)
    .bind(db_type.as_db_str())
    .fetch_one(&mut **tx)
    .await?;
    database_from_row_admin(&row)
}

async fn tx_get_database_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let row = sqlx::query(
        "SELECT id, server, db_name, db_type, created_at, updated_at, deleted_at \
         FROM permissions_databases \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| database_from_row_admin(&r)).transpose()
}

async fn tx_update_database(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    server: Option<&str>,
    db_name: Option<&str>,
    db_type: Option<DbType>,
) -> Result<Option<PermissionsDatabase>, RepoError> {
    let row = sqlx::query(
        "UPDATE permissions_databases \
         SET server = COALESCE($2, server), \
             db_name = COALESCE($3, db_name), \
             db_type = COALESCE($4, db_type), \
             updated_at = now() \
         WHERE id = $1 AND deleted_at IS NULL \
         RETURNING id, server, db_name, db_type, created_at, updated_at, deleted_at",
    )
    .bind(id)
    .bind(server)
    .bind(db_name)
    .bind(db_type.map(|t| t.as_db_str()))
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| database_from_row_admin(&r)).transpose()
}

async fn tx_soft_delete_database(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<bool, RepoError> {
    let res = sqlx::query(
        "UPDATE permissions_databases SET deleted_at = now() \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

fn database_from_row_admin(row: &sqlx::postgres::PgRow) -> Result<PermissionsDatabase, RepoError> {
    let db_type_str: String = row.try_get("db_type")?;
    Ok(PermissionsDatabase {
        id: row.try_get("id")?,
        server: row.try_get("server")?,
        db_name: row.try_get("db_name")?,
        db_type: DbType::parse(&db_type_str)?,
        created_at: row.try_get::<DateTime<Utc>, _>("created_at")?,
        updated_at: row.try_get::<DateTime<Utc>, _>("updated_at")?,
        deleted_at: row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?,
    })
}
