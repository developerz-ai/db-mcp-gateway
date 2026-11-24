//! Pure diff of a desired permissions document against the effective one.
//! Grants are compared by key `(subject, server, database, action)`; a key
//! present on both sides with different bodies (constraints, `except`,
//! `expires_at`) is a change. Several grants under one key compare as a
//! sorted list, so duplicates are a difference too.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::config::schema::Subject;
use crate::config::{Action, Constraints, Grant};

use super::grant_view::{constraints_json, subject_json};

/// `{"group": …}` or `{"user": …}`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectDoc {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

/// One grant of a desired document — the export's own shape, so an export
/// edited and posted back diffs cleanly. Export-only keys (`source`,
/// `grant_id`, `expired`, `profile`) are accepted and ignored: a profile is
/// already folded into `constraints`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocGrant {
    pub subject: SubjectDoc,
    pub server: String,
    pub database: String,
    pub action: Action,
    #[serde(default)]
    pub constraints: Constraints,
    #[serde(default)]
    pub except: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, rename = "source")]
    pub _source: Option<String>,
    #[serde(default, rename = "grant_id")]
    pub _grant_id: Option<uuid::Uuid>,
    #[serde(default, rename = "expired")]
    pub _expired: Option<bool>,
    #[serde(default, rename = "profile")]
    pub _profile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    subject: Subject,
    server: String,
    database: String,
    action: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Body {
    require_reason: bool,
    row_limit: Option<u32>,
    statement_timeout_ms: Option<u32>,
    except: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
}

pub(super) type Entry = (Key, Body);

pub(super) fn entry(subject: &Subject, grant: &Grant) -> Entry {
    let mut except = grant.except.clone();
    except.sort();
    let c = &grant.constraints;
    (
        Key {
            subject: subject.clone(),
            server: grant.server.clone(),
            database: grant.database.clone(),
            action: grant.action.as_str(),
        },
        Body {
            require_reason: c.require_reason,
            row_limit: c.row_limit,
            statement_timeout_ms: c.statement_timeout_ms,
            except,
            expires_at: grant.expires_at,
        },
    )
}

/// A desired grant as an entry; `Err` names what is wrong with it.
pub(super) fn desired_entry(doc: DocGrant) -> Result<Entry, String> {
    let subject = match (doc.subject.group, doc.subject.user) {
        (Some(group), None) => Subject::Group(group),
        (None, Some(user)) => Subject::User(user),
        _ => return Err("subject must name exactly one of `group` or `user`".into()),
    };
    let mut grant = Grant::new(&doc.server, &doc.database, doc.action, doc.constraints);
    grant.except = doc.except;
    grant.expires_at = doc.expires_at;
    Ok(entry(&subject, &grant))
}

/// `{add, remove, change, unchanged}`.
pub(super) fn diff(current: Vec<Entry>, desired: Vec<Entry>) -> JsonValue {
    let (current, desired) = (group(current), group(desired));
    let mut add = Vec::new();
    let mut change = Vec::new();
    let mut unchanged = 0usize;
    for (key, want) in &desired {
        match current.get(key) {
            None => add.extend(want.iter().map(|body| render(key, body))),
            Some(have) if have == want => unchanged += want.len(),
            Some(have) => change.push(json!({
                "key": render_key(key),
                "current": have.iter().map(render_body).collect::<Vec<_>>(),
                "desired": want.iter().map(render_body).collect::<Vec<_>>(),
            })),
        }
    }
    let remove: Vec<_> = current
        .iter()
        .filter(|(key, _)| !desired.contains_key(*key))
        .flat_map(|(key, bodies)| bodies.iter().map(move |body| render(key, body)))
        .collect();
    json!({ "add": add, "remove": remove, "change": change, "unchanged": unchanged })
}

fn group(entries: Vec<Entry>) -> BTreeMap<Key, Vec<Body>> {
    let mut grouped: BTreeMap<Key, Vec<Body>> = BTreeMap::new();
    for (key, body) in entries {
        grouped.entry(key).or_default().push(body);
    }
    grouped.values_mut().for_each(|bodies| bodies.sort());
    grouped
}

fn render_key(key: &Key) -> JsonValue {
    json!({
        "subject": subject_json(&key.subject),
        "server": key.server,
        "database": key.database,
        "action": key.action,
    })
}

fn render_body(body: &Body) -> JsonValue {
    json!({
        "constraints": constraints_json(&Constraints {
            require_reason: body.require_reason,
            row_limit: body.row_limit,
            statement_timeout_ms: body.statement_timeout_ms,
        }),
        "except": body.except,
        "expires_at": body.expires_at,
    })
}

fn render(key: &Key, body: &Body) -> JsonValue {
    let mut out = render_key(key);
    if let (Some(map), JsonValue::Object(body)) = (out.as_object_mut(), render_body(body)) {
        map.extend(body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(subject: Subject, db: &str, row_limit: Option<u32>) -> Entry {
        let constraints = Constraints {
            row_limit,
            ..Constraints::default()
        };
        entry(
            &subject,
            &Grant::new("s", db, Action::QueryRead, constraints),
        )
    }

    #[test]
    fn diff_reports_adds_removes_changes_and_unchanged() {
        let g = || Subject::Group("g".into());
        let u = || Subject::User("u".into());
        let current = vec![
            e(g(), "app", None),
            e(g(), "old", None),
            e(u(), "app", Some(5)),
        ];
        let desired = vec![
            e(g(), "app", None),
            e(g(), "new", None),
            e(u(), "app", Some(1)),
        ];
        let out = diff(current, desired);
        assert_eq!(out["unchanged"], 1);
        assert_eq!(out["add"][0]["database"], "new");
        assert_eq!(out["remove"][0]["database"], "old");
        assert_eq!(out["change"][0]["key"]["subject"]["user"], "u");
        assert_eq!(
            out["change"][0]["current"][0]["constraints"]["row_limit"],
            5
        );
        assert_eq!(
            out["change"][0]["desired"][0]["constraints"]["row_limit"],
            1
        );
    }

    #[test]
    fn desired_subject_must_be_exactly_one() {
        let doc: DocGrant = serde_json::from_value(json!({
            "subject": { "group": "g", "user": "u" },
            "server": "s", "database": "*", "action": "query_read",
        }))
        .unwrap();
        assert!(desired_entry(doc).is_err());
    }
}
