//! Collections a command reads besides its own. An aggregation stage can
//! name another collection — `$lookup` / `$graphLookup` `from`,
//! `$unionWith` — anywhere in the pipeline, nested pipelines and `$facet`
//! branches included, so the `system.*` refusal applies to every one of
//! them. A namespace that is not a plain collection name (`{db, coll}`, a
//! `db` beside `coll`) reaches past the granted database and is refused.

use serde_json::Value;

use super::{RejectReason, is_system_collection};

/// Stages whose argument names a collection to read.
const NAMESPACE_STAGES: &[&str] = &["$lookup", "$graphLookup", "$unionWith"];

/// The expression operator whose argument is data, never evaluated: a
/// `$lookup` key inside it is a value, not a stage.
const LITERAL: &str = "$literal";

/// Every namespace-naming stage under `value`, at any depth, outside
/// `$literal` data.
pub(super) fn check_namespaces(command: &str, value: &Value) -> Result<(), RejectReason> {
    match value {
        Value::Object(map) => map.iter().try_for_each(|(key, child)| {
            if key == LITERAL {
                return Ok(());
            }
            if let Some(stage) = NAMESPACE_STAGES.iter().copied().find(|s| s == key) {
                check_stage(command, stage, child)?;
            }
            check_namespaces(command, child)
        }),
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| check_namespaces(command, item)),
        _ => Ok(()),
    }
}

/// The collection `stage` names in `spec`, if any, refused when it is a
/// `system.*` collection or not a plain name in this database.
fn check_stage(command: &str, stage: &'static str, spec: &Value) -> Result<(), RejectReason> {
    let named = match (stage, spec) {
        ("$unionWith", Value::String(_)) => Some(spec),
        (_, Value::Object(fields)) if fields.contains_key("db") => {
            return Err(RejectReason::ForeignNamespace(stage));
        }
        ("$unionWith", Value::Object(fields)) => fields.get("coll"),
        (_, Value::Object(fields)) => fields.get("from"),
        // Not a stage document: the server refuses it before reading.
        _ => None,
    };
    match named {
        None => Ok(()),
        Some(Value::String(name)) if is_system_collection(name) => {
            Err(RejectReason::SystemCollection(command.to_owned()))
        }
        Some(Value::String(_)) => Ok(()),
        Some(_) => Err(RejectReason::ForeignNamespace(stage)),
    }
}
