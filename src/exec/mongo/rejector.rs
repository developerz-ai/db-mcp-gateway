//! Read-only enforcement for mongo commands. Gateway-side defense in depth
//! on top of the least-privilege mongo role.
//!
//! Security-required (CLAUDE.md). Spec 12 §"Mongo adapter" / lines 231–235.
//!
//! Why gateway-side at all? Mongo doesn't expose a single "READ ONLY" role
//! flag the way Postgres does. Some commands that look read-only can write
//! — `$out` and `$merge` in an aggregation pipeline materialize a result
//! collection; `$function` and `$where` execute arbitrary JavaScript with
//! side-effect potential. The connection still uses a read-only mongo role
//! as the primary guardrail; the rejector is the secondary one.
//!
//! Contract:
//!  1. The first key of the JSON object is the *command name*. Only
//!     `find`, `aggregate`, `count`, `distinct` pass — matches issue #57
//!     scope. Spec 12 §234 lists a broader allow set; the broader items
//!     (`listCollections`, `listIndexes`, …) land with execution in #58.
//!  2. The four denied operators — `$out`, `$merge`, `$function`,
//!     `$where` — are rejected at *any* depth in the document tree.
//!     Anything else (an unknown `$op`, a write-shaped value, a top-level
//!     `update` command, …) is rejected by virtue of failing the command
//!     allow-list check at the top level.
//!
//! Mongo's wire format is BSON, but the gateway accepts the command as
//! JSON text (the same channel as pg's SQL string). serde_json parses it;
//! the rejector walks the resulting `serde_json::Value` tree. Sticking to
//! the JSON layer keeps the rejector decoupled from `bson` and avoids
//! pulling extended-JSON's `{$date: ...}` ambiguity into the deny check.

use serde_json::Value;

/// Allowed top-level command names. The first JSON object key is the
/// command name (mongo's wire convention). Anything outside this set is
/// rejected — including writes (`insert`, `update`, `delete`, `drop`,
/// `findAndModify`, `bulkWrite`, `createIndex`) and admin commands.
const ALLOWED_COMMANDS: &[&str] = &["find", "aggregate", "count", "distinct"];

/// Denied operator keys. Reject at any depth — an aggregation pipeline
/// stage, a projection, a filter, an embedded subdocument: anywhere a `$`
/// prefix appears. The four operators were chosen because each can drive
/// a write or arbitrary JS execution:
///
/// - `$out` — writes the pipeline output to a collection.
/// - `$merge` — same, but with upsert semantics (mongo's `$out` successor).
/// - `$function` — server-side JS evaluation (any side effect).
/// - `$where` — JS predicate evaluation. Static analysis of arbitrary JS
///   for purity is impossible, so the conservative choice is reject all.
const DENIED_OPERATORS: &[&str] = &["$out", "$merge", "$function", "$where"];

/// Why a command was rejected. `Display` is operator-facing and never
/// carries any of the command's *values* — the structured rejection is the
/// audit signal; values stay in the original command for the audit row.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RejectReason {
    #[error("mongo command is not valid JSON")]
    Malformed,

    #[error("mongo command must be a JSON object with at least one field")]
    EmptyCommand,

    #[error("mongo command `{0}` is not in the read-only allow set")]
    DisallowedCommand(String),

    #[error("mongo command uses disallowed operator `{0}`")]
    DisallowedOperator(&'static str),
}

/// Read-only enforcement for a mongo command. Returns `Ok(())` iff the
/// command name is in [`ALLOWED_COMMANDS`] AND no [`DENIED_OPERATORS`]
/// appear anywhere in the parsed tree.
pub fn validate_command(json: &str) -> Result<(), RejectReason> {
    let value: Value = serde_json::from_str(json).map_err(|_| RejectReason::Malformed)?;
    let object = value.as_object().ok_or(RejectReason::EmptyCommand)?;

    // Mongo wire convention: the first field is the command name.
    let (command, _) = object.iter().next().ok_or(RejectReason::EmptyCommand)?;
    if !ALLOWED_COMMANDS.contains(&command.as_str()) {
        return Err(RejectReason::DisallowedCommand(command.clone()));
    }

    walk_for_denied(&value)
}

/// Recursive walk for any `$op` key in [`DENIED_OPERATORS`]. The walk is
/// over the whole tree because mongo's deny-shaped operators can appear in
/// pipelines, projections, filters, sub-pipelines (`$lookup`'s pipeline),
/// `$facet` branches, or as the *value* of a key.
fn walk_for_denied(value: &Value) -> Result<(), RejectReason> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if let Some(denied) = denied_match(key) {
                    return Err(RejectReason::DisallowedOperator(denied));
                }
                walk_for_denied(child)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                walk_for_denied(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn denied_match(key: &str) -> Option<&'static str> {
    DENIED_OPERATORS
        .iter()
        .copied()
        .find(|denied| *denied == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table-driven coverage of the allow / deny matrix. One row = one
    /// case; the assertion is the same shape for all so a future addition
    /// (e.g. listCollections in #58) is one line.
    #[test]
    fn rejector_matrix() {
        let cases: &[(&str, &str, Result<(), RejectReason>)] = &[
            // --- allowed reads -------------------------------------------------
            (
                "find allowed",
                r#"{"find":"users","filter":{"active":true},"limit":10}"#,
                Ok(()),
            ),
            (
                "aggregate allowed",
                r#"{"aggregate":"users","pipeline":[{"$match":{"active":true}},{"$group":{"_id":"$role","n":{"$sum":1}}}],"cursor":{}}"#,
                Ok(()),
            ),
            (
                "count allowed",
                r#"{"count":"users","query":{"active":true}}"#,
                Ok(()),
            ),
            (
                "distinct allowed",
                r#"{"distinct":"users","key":"role"}"#,
                Ok(()),
            ),
            // --- writes denied by command allow-list ---------------------------
            (
                "insert denied",
                r#"{"insert":"users","documents":[{"x":1}]}"#,
                Err(RejectReason::DisallowedCommand("insert".to_string())),
            ),
            (
                "update denied",
                r#"{"update":"users","updates":[{"q":{},"u":{"$set":{"x":1}}}]}"#,
                Err(RejectReason::DisallowedCommand("update".to_string())),
            ),
            (
                "delete denied",
                r#"{"delete":"users","deletes":[{"q":{},"limit":1}]}"#,
                Err(RejectReason::DisallowedCommand("delete".to_string())),
            ),
            (
                "findAndModify denied",
                r#"{"findAndModify":"users","query":{},"update":{"$set":{"x":1}}}"#,
                Err(RejectReason::DisallowedCommand("findAndModify".to_string())),
            ),
            (
                "bulkWrite denied",
                r#"{"bulkWrite":"users","ops":[]}"#,
                Err(RejectReason::DisallowedCommand("bulkWrite".to_string())),
            ),
            (
                "drop denied",
                r#"{"drop":"users"}"#,
                Err(RejectReason::DisallowedCommand("drop".to_string())),
            ),
            // --- operators denied at any depth ---------------------------------
            (
                "$out in pipeline denied",
                r#"{"aggregate":"users","pipeline":[{"$out":"snap"}],"cursor":{}}"#,
                Err(RejectReason::DisallowedOperator("$out")),
            ),
            (
                "$merge in pipeline denied",
                r#"{"aggregate":"users","pipeline":[{"$merge":{"into":"snap"}}],"cursor":{}}"#,
                Err(RejectReason::DisallowedOperator("$merge")),
            ),
            (
                "$function in projection denied",
                r#"{"aggregate":"users","pipeline":[{"$project":{"name":{"$function":{"body":"function(){return 1}","args":[],"lang":"js"}}}}],"cursor":{}}"#,
                Err(RejectReason::DisallowedOperator("$function")),
            ),
            (
                "$where in find denied",
                r#"{"find":"users","filter":{"$where":"this.role == 'admin'"}}"#,
                Err(RejectReason::DisallowedOperator("$where")),
            ),
            (
                "$out deeply nested inside $facet denied",
                r#"{"aggregate":"users","pipeline":[{"$facet":{"snap":[{"$out":"target"}]}}],"cursor":{}}"#,
                Err(RejectReason::DisallowedOperator("$out")),
            ),
            (
                "$where inside $lookup sub-pipeline denied",
                r#"{"aggregate":"users","pipeline":[{"$lookup":{"from":"orders","let":{},"pipeline":[{"$match":{"$where":"true"}}],"as":"o"}}],"cursor":{}}"#,
                Err(RejectReason::DisallowedOperator("$where")),
            ),
            // --- malformed / empty inputs --------------------------------------
            (
                "non-JSON rejected",
                "definitely not JSON",
                Err(RejectReason::Malformed),
            ),
            (
                "JSON array rejected (not an object)",
                "[1,2,3]",
                Err(RejectReason::EmptyCommand),
            ),
            (
                "empty object rejected",
                "{}",
                Err(RejectReason::EmptyCommand),
            ),
        ];

        for (label, input, expected) in cases {
            let actual = validate_command(input);
            assert_eq!(
                actual.as_ref().map_err(|e| e.clone()),
                expected.as_ref().map_err(|e| e.clone()),
                "case {label:?}: input={input:?}, got {actual:?}",
            );
        }
    }

    /// `RejectReason::Display` carries only the operator-facing message —
    /// never the command's *values* (which can include user PII / queries).
    /// Audit logs get the structured reason; renderings get the safe text.
    #[test]
    fn display_never_leaks_command_values() {
        let secret_filter = r#"{"find":"users","filter":{"$where":"this.ssn == '123-45-6789'"}}"#;
        let err = validate_command(secret_filter).unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("$where"));
        assert!(!rendered.contains("123-45-6789"), "leaked SSN: {rendered}");
        assert!(!rendered.contains("ssn"), "leaked field name: {rendered}");
    }
}
