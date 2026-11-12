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
//!     `find`, `aggregate`, `count`, `distinct`, `listCollections` and
//!     `listIndexes` pass.
//!  2. Every other top-level key must be in that command's own allow-list
//!     ([`allowed_fields`]). This is what stops a read command from carrying
//!     session or routing state into the driver: `$db` (re-targeting the
//!     command at another database), `$readPreference`, `lsid`, `txnNumber`,
//!     `autocommit`, `startTransaction`, `writeConcern` — none is listed, so
//!     none passes.
//!  3. The denied operators — `$out`, `$merge`, `$function`, `$where`,
//!     `$accumulator` — are rejected at *any* depth in the document tree.
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
const ALLOWED_COMMANDS: &[&str] = &[
    "find",
    "aggregate",
    "count",
    "distinct",
    "listCollections",
    "listIndexes",
];

/// Top-level keys each allowed command may carry besides its name. Shape and
/// read options only: no session, transaction, write-concern or routing
/// field, and no cursor-lifetime knob (`tailable`, `awaitData`,
/// `noCursorTimeout`) that would let one call pin a server cursor.
/// `maxTimeMS` and `comment` are accepted but always overwritten by the
/// gateway (budget and cancel marker).
fn allowed_fields(command: &str) -> &'static [&'static str] {
    match command {
        "find" => &[
            "filter",
            "sort",
            "projection",
            "hint",
            "skip",
            "limit",
            "batchSize",
            "singleBatch",
            "comment",
            "maxTimeMS",
            "max",
            "min",
            "returnKey",
            "showRecordId",
            "allowPartialResults",
            "collation",
            "allowDiskUse",
            "let",
        ],
        "aggregate" => &[
            "pipeline",
            "cursor",
            "allowDiskUse",
            "maxTimeMS",
            "collation",
            "hint",
            "comment",
            "let",
        ],
        "count" => &[
            "query",
            "limit",
            "skip",
            "hint",
            "maxTimeMS",
            "collation",
            "comment",
        ],
        "distinct" => &["key", "query", "collation", "comment", "hint", "maxTimeMS"],
        "listCollections" => &[
            "filter",
            "nameOnly",
            "authorizedCollections",
            "cursor",
            "comment",
            "maxTimeMS",
        ],
        "listIndexes" => &["cursor", "comment", "maxTimeMS"],
        _ => &[],
    }
}

/// Denied operator keys. Reject at any depth — an aggregation pipeline
/// stage, a projection, a filter, an embedded subdocument: anywhere a `$`
/// prefix appears. Each operator was chosen because it can drive a write
/// or arbitrary JS execution:
///
/// - `$out` — writes the pipeline output to a collection.
/// - `$merge` — same, but with upsert semantics (mongo's `$out` successor).
/// - `$function` — server-side JS evaluation (any side effect).
/// - `$where` — JS predicate evaluation. Static analysis of arbitrary JS
///   for purity is impossible, so the conservative choice is reject all.
/// - `$accumulator` — custom aggregation accumulator running server-side
///   JS (`init`/`accumulate`/`merge`/`finalize`), reachable inside an
///   allowed `aggregate` pipeline (e.g. nested in `$group`). Same JS
///   execution risk class as `$function`/`$where`.
const DENIED_OPERATORS: &[&str] = &["$out", "$merge", "$function", "$where", "$accumulator"];

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

    #[error("mongo command `{command}` does not allow top-level field `{field}`")]
    DisallowedField { command: String, field: String },
}

/// Read-only enforcement for a mongo command. Returns `Ok(())` iff the
/// command name is in [`ALLOWED_COMMANDS`], every other top-level key is in
/// its [`allowed_fields`], AND no [`DENIED_OPERATORS`] appear anywhere in
/// the parsed tree.
pub fn validate_command(json: &str) -> Result<(), RejectReason> {
    let value: Value = serde_json::from_str(json).map_err(|_| RejectReason::Malformed)?;
    let object = value.as_object().ok_or(RejectReason::EmptyCommand)?;

    // Mongo wire convention: the first field is the command name.
    let (command, _) = object.iter().next().ok_or(RejectReason::EmptyCommand)?;
    if !ALLOWED_COMMANDS.contains(&command.as_str()) {
        return Err(RejectReason::DisallowedCommand(command.clone()));
    }
    let allowed = allowed_fields(command);
    if let Some(field) = object
        .keys()
        .skip(1)
        .find(|k| !allowed.contains(&k.as_str()))
    {
        return Err(RejectReason::DisallowedField {
            command: command.clone(),
            field: field.clone(),
        });
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
mod tests;
