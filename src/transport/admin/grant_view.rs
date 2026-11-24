//! JSON views of an evaluated grant, shared by `explain` and the
//! export/diff document so the two describe a grant identically.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value as JsonValue, json};
use uuid::Uuid;

use crate::config::schema::Subject;
use crate::config::{Constraints, Grant};

pub(super) fn subject_json(subject: &Subject) -> JsonValue {
    match subject {
        Subject::Group(name) => json!({ "group": name }),
        Subject::User(sub) => json!({ "user": sub }),
    }
}

pub(super) fn constraints_json(c: &Constraints) -> JsonValue {
    json!({
        "require_reason": c.require_reason,
        "row_limit": c.row_limit,
        "statement_timeout_ms": c.statement_timeout_ms,
    })
}

/// Where a grant lives: a YAML block, or a DB row by id.
#[derive(Debug, Clone, Copy)]
pub(super) enum Origin {
    Yaml,
    Db(Uuid),
}

/// `{source, subject, server, database, action, constraints, …}`; optional
/// keys appear only when set, so an export round-trips into a diff body.
pub(super) fn grant_json(
    origin: Origin,
    subject: &Subject,
    grant: &Grant,
    now: DateTime<Utc>,
) -> JsonValue {
    let mut out = Map::new();
    match origin {
        Origin::Yaml => {
            out.insert("source".into(), json!("yaml"));
        }
        Origin::Db(id) => {
            out.insert("source".into(), json!("db"));
            out.insert("grant_id".into(), json!(id));
        }
    }
    out.insert("subject".into(), subject_json(subject));
    out.insert("server".into(), json!(grant.server));
    out.insert("database".into(), json!(grant.database));
    out.insert("action".into(), json!(grant.action.as_str()));
    out.insert("constraints".into(), constraints_json(&grant.constraints));
    if !grant.except.is_empty() {
        out.insert("except".into(), json!(grant.except));
    }
    if let Some(profile) = &grant.profile {
        out.insert("profile".into(), json!(profile));
    }
    if let Some(at) = grant.expires_at {
        out.insert("expires_at".into(), json!(at));
        out.insert("expired".into(), json!(!grant.is_live_at(now)));
    }
    JsonValue::Object(out)
}
