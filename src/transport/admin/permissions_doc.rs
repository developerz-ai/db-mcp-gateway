//! `GET /admin/v1/permissions/export` — the effective permissions, YAML ∪
//! DB, as one document — and `POST /admin/v1/permissions/diff`, a desired
//! document compared against it. Both read-only; each audited before its
//! response (`admin.permissions_export` / `admin.permissions_diff`).

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, State};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::authz;
use crate::config::schema::Subject;
use crate::config::{ConfigFile, Grant};
use crate::state::permissions::pg::export::all_live_grants;

use super::ReadState;
use super::error::AdminError;
use super::grant_view::{Origin, grant_json};
use super::middleware::AdminActor;
use super::permissions_diff::{DocGrant, Entry, desired_entry, diff, entry};
use super::read_audit::{AdminRead, ReadScope, audit_read};
use super::validation::{internal, invalid_body};

/// Body limit of `POST /admin/v1/permissions/diff`: an export of 10,000
/// grants with full constraints, with room to spare, where every other admin
/// body is one record. The only size bound on a diff: a grant count limit
/// that followed the store's size refused an export once a grant was revoked
/// from a store past it, and the body is parsed whole before any count, so
/// this limit already bounds the sort (a minimal grant is ~80 bytes).
pub(super) const DIFF_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Every grant evaluation can use: YAML blocks, then every live DB grant
/// (expired ones included, flagged — they are rows an operator still owns).
struct Effective {
    yaml: Vec<(Subject, Grant)>,
    db: Vec<(uuid::Uuid, Subject, Grant)>,
}

async fn load_effective(state: &ReadState, rid: &str) -> Result<Effective, AdminError> {
    let config: std::sync::Arc<ConfigFile> = state.config.load_full();
    let yaml = config
        .permissions
        .iter()
        .flat_map(|p| p.grants.iter().map(|g| (p.subject.clone(), g.clone())))
        .collect();
    let rows = all_live_grants(&state.state_db)
        .await
        .map_err(|err| internal("export grants", err, rid))?;
    let db = rows
        .into_iter()
        .map(|(sub, row)| {
            let id = row.id;
            authz::to_config_grant(row).map(|grant| (id, Subject::User(sub), grant))
        })
        .collect::<Result<_, _>>()
        .map_err(|err| internal("export decode", err, rid))?;
    Ok(Effective { yaml, db })
}

impl Effective {
    fn len(&self) -> usize {
        self.yaml.len() + self.db.len()
    }

    fn document(&self, now: DateTime<Utc>) -> Vec<JsonValue> {
        let yaml = self
            .yaml
            .iter()
            .map(|(subject, grant)| grant_json(Origin::Yaml, subject, grant, now));
        let db = self
            .db
            .iter()
            .map(|(id, subject, grant)| grant_json(Origin::Db(*id), subject, grant, now));
        yaml.chain(db).collect()
    }

    fn entries(&self) -> Vec<Entry> {
        let yaml = self.yaml.iter().map(|(s, g)| entry(s, g));
        let db = self.db.iter().map(|(_, s, g)| entry(s, g));
        yaml.chain(db).collect()
    }
}

pub async fn export(
    State(state): State<ReadState>,
    Extension(actor): Extension<AdminActor>,
) -> Result<Json<JsonValue>, AdminError> {
    let rid = actor.request_id.as_str();
    let effective = load_effective(&state, rid).await?;
    let scope = ReadScope {
        row_count: i64::try_from(effective.len()).ok(),
        ..ReadScope::default()
    };
    audit_read(&state.state_db, &actor, AdminRead::Export, scope).await?;
    let now = Utc::now();
    Ok(Json(json!({
        "generated_at": now,
        "grants": effective.document(now),
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffRequest {
    pub grants: Vec<DocGrant>,
    /// Ignored; present so an export posts back unchanged.
    #[serde(default, rename = "generated_at")]
    pub _generated_at: Option<DateTime<Utc>>,
}

pub async fn diff_document(
    State(state): State<ReadState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<DiffRequest>, JsonRejection>,
) -> Result<Json<JsonValue>, AdminError> {
    let rid = actor.request_id.as_str();
    let Json(body) = body.map_err(|rejection| invalid_body(&rejection, rid))?;
    let desired = body
        .grants
        .into_iter()
        .enumerate()
        .map(|(i, doc)| {
            desired_entry(doc).map_err(|msg| {
                AdminError::invalid(format!("grants[{i}]: {msg}")).with_request_id(rid)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let effective = load_effective(&state, rid).await?;
    let scope = ReadScope {
        row_count: i64::try_from(effective.len()).ok(),
        ..ReadScope::default()
    };
    audit_read(&state.state_db, &actor, AdminRead::Diff, scope).await?;
    Ok(Json(diff(effective.entries(), desired)))
}
