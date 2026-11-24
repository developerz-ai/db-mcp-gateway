//! `POST /admin/v1/grants/batch` — many grant upserts and deletes in ONE
//! audited transaction: every change commits with its own
//! `permissions_audit` row, or none does.
//!
//! An upsert is keyed by `(user_id, target, action)`: the oldest live grant
//! with that key is updated in place (constraints and `expires_at` replaced),
//! otherwise a grant is created. An upsert that would change nothing writes
//! nothing and audits nothing.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::audit::permissions::{PermissionsAuditAction as Action, PermissionsAuditTargetType};
use crate::state::permissions::pg::{export, grants, users};
use crate::state::permissions::{GrantAction, GrantTarget, PermissionsChange};

use super::super::audited_tx::AuditedTx;
use super::super::error::AdminError;
use super::super::middleware::AdminActor;
use super::super::payload::grant_payload;
use super::super::validation::{invalid_body, store_error};
use super::validation::{
    constraints_to_json, future_expiry, map_create_grant_error, parse_action, parse_grant_target,
    positive_bounds,
};
use super::{CreateGrantRequest, GrantResponse, GrantsState};

const GRANT: PermissionsAuditTargetType = PermissionsAuditTargetType::Grant;

/// Changes one batch may carry; larger sets hold their row locks too long.
pub const MAX_BATCH_CHANGES: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    pub changes: Vec<BatchChange>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BatchChange {
    Upsert(CreateGrantRequest),
    Delete { id: Uuid },
}

#[derive(Debug, Serialize)]
pub struct BatchResult {
    pub index: usize,
    /// `created`, `updated`, `unchanged` or `deleted`.
    pub op: &'static str,
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<GrantResponse>,
}

/// A change validated before the transaction opens.
enum Planned {
    Upsert {
        user_id: Uuid,
        target: GrantTarget,
        action: GrantAction,
        constraints: JsonValue,
        expires_at: Option<DateTime<Utc>>,
    },
    Delete(Uuid),
}

pub async fn batch(
    State(state): State<GrantsState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<BatchRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, AdminError> {
    let rid = actor.request_id.as_str();
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    if body.changes.is_empty() || body.changes.len() > MAX_BATCH_CHANGES {
        return Err(AdminError::invalid(format!(
            "changes must hold 1..={MAX_BATCH_CHANGES} entries"
        ))
        .with_request_id(rid));
    }
    let planned = body
        .changes
        .iter()
        .enumerate()
        .map(|(i, change)| plan(change, &state.known_servers, rid).map_err(|e| at(i, e, rid)))
        .collect::<Result<Vec<_>, _>>()?;

    let mut atx = AuditedTx::begin_locked(&state.state_db, &actor).await?;
    let mut results = Vec::with_capacity(planned.len());
    let mut touched = BTreeSet::new();
    for (index, change) in planned.into_iter().enumerate() {
        let (result, user_id) = apply(&mut atx, index, change).await?;
        touched.insert(user_id);
        results.push(result);
    }
    let change = change_for_users(&mut atx, &touched).await?;
    atx.commit(&state.cache, Some(change)).await?;
    Ok(Json(serde_json::json!({ "results": results })))
}

fn plan(change: &BatchChange, known_servers: &[String], rid: &str) -> Result<Planned, AdminError> {
    match change {
        BatchChange::Delete { id } => Ok(Planned::Delete(*id)),
        BatchChange::Upsert(body) => {
            let target = parse_grant_target(body, known_servers, rid)?;
            let action = parse_action(&body.action, rid)?;
            positive_bounds(&body.constraints, rid)?;
            future_expiry(body.expires_at, rid)?;
            Ok(Planned::Upsert {
                user_id: body.user_id,
                target,
                action,
                constraints: constraints_to_json(&body.constraints),
                expires_at: body.expires_at,
            })
        }
    }
}

async fn apply(
    atx: &mut AuditedTx<'_>,
    index: usize,
    change: Planned,
) -> Result<(BatchResult, Uuid), AdminError> {
    let rid = atx.request_id();
    match change {
        Planned::Delete(id) => {
            let before = grants::tx_lock_grant(atx.tx(), id)
                .await
                .map_err(|err| store_error("lock_grant", err, rid))?
                .ok_or_else(|| at(index, AdminError::invalid("grant not found"), rid))?;
            grants::tx_revoke_grant(atx.tx(), id)
                .await
                .map_err(|err| store_error("revoke_grant", err, rid))?;
            atx.audit(
                Action::Delete,
                GRANT,
                id,
                Some(grant_payload(&before)),
                None,
            )
            .await?;
            Ok((result(index, "deleted", id, None), before.user_id))
        }
        Planned::Upsert {
            user_id,
            target,
            action,
            constraints,
            expires_at,
        } => {
            let existing = export::tx_lock_grant_by_key(atx.tx(), user_id, &target, action)
                .await
                .map_err(|err| store_error("lock_grant_by_key", err, rid))?;
            let Some(before) = existing else {
                let created = grants::tx_create_grant(
                    atx.tx(),
                    user_id,
                    &target,
                    action,
                    &constraints,
                    expires_at,
                )
                .await
                .map_err(|err| map_create_grant_error(err, rid))?
                .ok_or_else(|| {
                    at(
                        index,
                        AdminError::invalid("user or database does not exist"),
                        rid,
                    )
                })?;
                let payload = grant_payload(&created);
                atx.audit(Action::Create, GRANT, created.id, None, Some(payload))
                    .await?;
                return Ok((with_grant(index, "created", created), user_id));
            };
            if before.constraints == constraints && before.expires_at == expires_at {
                return Ok((with_grant(index, "unchanged", before), user_id));
            }
            let after =
                grants::tx_update_grant(atx.tx(), before.id, None, &constraints, expires_at)
                    .await
                    .map_err(|err| store_error("update_grant", err, rid))?
                    .ok_or_else(|| at(index, AdminError::not_found(), rid))?;
            let (b, a) = (grant_payload(&before), grant_payload(&after));
            atx.audit(Action::Update, GRANT, after.id, Some(b), Some(a))
                .await?;
            Ok((with_grant(index, "updated", after), user_id))
        }
    }
}

fn result(index: usize, op: &'static str, id: Uuid, grant: Option<GrantResponse>) -> BatchResult {
    BatchResult {
        index,
        op,
        id,
        grant,
    }
}

fn with_grant(
    index: usize,
    op: &'static str,
    grant: crate::state::permissions::PermissionsGrant,
) -> BatchResult {
    result(index, op, grant.id, Some(GrantResponse::from(grant)))
}

/// Prefix a validation error with the change it came from. Non-`invalid`
/// errors (conflict, internal) pass through unchanged.
fn at(index: usize, err: AdminError, rid: &str) -> AdminError {
    err.prefixed(&format!("changes[{index}]: "))
        .with_request_id(rid)
}

/// One touched user → invalidate that user; several → everyone (a
/// `PermissionsChange` names at most one subject).
async fn change_for_users(
    atx: &mut AuditedTx<'_>,
    user_ids: &BTreeSet<Uuid>,
) -> Result<PermissionsChange, AdminError> {
    let [user_id] = user_ids.iter().copied().collect::<Vec<_>>()[..] else {
        return Ok(PermissionsChange::All);
    };
    let rid = atx.request_id();
    let sub = users::tx_user_sub(atx.tx(), user_id)
        .await
        .map_err(|err| store_error("user_sub", err, rid))?;
    Ok(sub.map_or(PermissionsChange::All, PermissionsChange::User))
}
