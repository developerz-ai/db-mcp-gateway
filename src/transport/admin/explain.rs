//! `POST /admin/v1/explain` — why a `(user | group, server, database,
//! action)` is allowed or denied: the grants that matched and the merged
//! constraints, computed by the evaluator itself
//! ([`authz::matching_grants`] + [`authz::decide`]), so the answer is the
//! decision a real call would get. Read-only; audited as `admin.explain`.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, State};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::auth::{Identity, IdentityKind, SessionId};
use crate::authz::{self, Decision, GrantSource};
use crate::config::schema::Subject;
use crate::config::{Action, Grant};
use crate::state::permissions::pg::export::live_user_by_sub;

use super::ReadState;
use super::error::AdminError;
use super::grant_view::{Origin, constraints_json, grant_json, subject_json};
use super::middleware::AdminActor;
use super::read_audit::{AdminRead, ReadScope, audit_read};
use super::validation::{internal, invalid_body, trimmed_non_empty};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplainRequest {
    /// SSO subject to explain for. Exactly one of `user` / `group`.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    /// With `user`: the group claims to assume. Absent → the groups cached
    /// on the user's `permissions_users` row (none if there is no row).
    #[serde(default)]
    pub groups: Option<Vec<String>>,
    pub server: String,
    pub database: String,
    pub action: Action,
}

pub async fn explain(
    State(state): State<ReadState>,
    Extension(actor): Extension<AdminActor>,
    body: Result<Json<ExplainRequest>, JsonRejection>,
) -> Result<Json<JsonValue>, AdminError> {
    let rid = actor.request_id.as_str();
    let Json(body) = body.map_err(|_| invalid_body(rid))?;
    let subject = parse_subject(&body, rid)?;
    let server = trimmed_non_empty(&body.server, "server", rid)?;
    let database = trimmed_non_empty(&body.database, "database", rid)?;

    let (identity, db_rows) = match &subject {
        Subject::User(sub) => {
            let groups = match body.groups.clone() {
                Some(groups) => groups,
                None => live_user_by_sub(&state.state_db, sub)
                    .await
                    .map_err(|err| internal("explain user", err, rid))?
                    .map(|u| u.groups)
                    .unwrap_or_default(),
            };
            let rows = state
                .repo
                .live_grants_for_sub(sub)
                .await
                .map_err(|err| internal("explain grants", err, rid))?;
            (identity(sub, groups), rows)
        }
        // No `user:` block can match an empty subject (boot rejects blank
        // ones), so a group question sees group grants only.
        Subject::Group(group) => (identity("", vec![group.clone()]), Vec::new()),
    };
    let db_ids: Vec<_> = db_rows.iter().map(|r| r.id).collect();
    let db_grants = db_rows
        .into_iter()
        .map(authz::to_config_grant)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| internal("explain decode", err, rid))?;

    let config = state.config.load();
    let now = Utc::now();
    let target = (server.as_str(), database.as_str());
    let matches: Vec<_> = authz::matching_grants(
        &identity,
        body.action,
        target,
        &config.permissions,
        &db_grants,
        now,
    )
    .collect();
    let decision = authz::decide(matches.iter().copied());
    let matched = matches
        .iter()
        .map(|m| match m.source {
            GrantSource::Yaml(subject) => Ok(grant_json(Origin::Yaml, subject, m.grant, now)),
            GrantSource::Db(index) => db_origin(&db_ids, index, rid)
                .map(|origin| grant_json(origin, &subject, m.grant, now)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let expired = expired_db_grants(&db_grants, &db_ids, body.action, target, now)
        .map(|(id, grant)| grant_json(Origin::Db(id), &subject, grant, now))
        .collect::<Vec<_>>();
    let declared = config
        .servers
        .iter()
        .any(|s| s.name == server && s.databases.iter().any(|d| d.name == database));

    audit_read(
        &state.state_db,
        &actor,
        AdminRead::Explain,
        ReadScope {
            server: Some(&server),
            database: Some(&database),
            row_count: i64::try_from(matched.len()).ok(),
        },
    )
    .await?;
    let (verdict, constraints) = match &decision {
        Decision::Allow { constraints } => ("allow", constraints_json(constraints)),
        Decision::Deny => ("deny", JsonValue::Null),
    };
    Ok(Json(json!({
        "decision": verdict,
        "constraints": constraints,
        "subject": subject_json(&subject),
        "groups": identity.groups,
        "server": server,
        "database": database,
        "action": body.action.as_str(),
        "target_declared": declared,
        "matched": matched,
        "expired": expired,
    })))
}

fn parse_subject(body: &ExplainRequest, rid: &str) -> Result<Subject, AdminError> {
    match (&body.user, &body.group, &body.groups) {
        (Some(user), None, _) => Ok(Subject::User(trimmed_non_empty(user, "user", rid)?)),
        (None, Some(group), None) => Ok(Subject::Group(trimmed_non_empty(group, "group", rid)?)),
        (None, Some(_), Some(_)) => Err(AdminError::invalid(
            "`groups` applies only to a `user` question",
        )
        .with_request_id(rid)),
        _ => Err(AdminError::invalid("set exactly one of `user` or `group`").with_request_id(rid)),
    }
}

/// An SSO identity for the question. SSO, not service: a service identity
/// never reads DB grants or matches a `user:` block, so explaining one is
/// explaining its group.
fn identity(sub: &str, groups: Vec<String>) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: sub.to_string(),
        user_email: String::new(),
        groups,
        issued_at: Utc::now(),
        kind: IdentityKind::Sso,
    }
}

fn db_origin(ids: &[uuid::Uuid], index: usize, rid: &str) -> Result<Origin, AdminError> {
    ids.get(index)
        .map(|id| Origin::Db(*id))
        .ok_or_else(|| internal("explain index", (), rid))
}

/// DB grants that would match but for their expiry — the usual answer to
/// "it worked yesterday".
fn expired_db_grants<'a>(
    grants: &'a [Grant],
    ids: &'a [uuid::Uuid],
    action: Action,
    (server, database): (&'a str, &'a str),
    now: chrono::DateTime<Utc>,
) -> impl Iterator<Item = (uuid::Uuid, &'a Grant)> + 'a {
    grants
        .iter()
        .zip(ids.iter().copied())
        .filter(move |(g, _)| {
            !g.is_live_at(now) && authz::grant_applies(g, action, server, database)
        })
        .map(|(g, id)| (id, g))
}
