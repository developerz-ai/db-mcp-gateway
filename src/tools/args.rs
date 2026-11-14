//! The argument edge every `tools/call` crosses before any tool runs: string
//! values and keys are bounded and free of control characters, and a tool's
//! arguments deserialise into its typed struct or name what was wrong.
//!
//! Bounding here, once, keeps an unbounded or NUL-bearing value out of the
//! tracing span, the intent row, the audit row and the target: Postgres
//! refuses NUL in `text` (SQLSTATE 22021) and an index row past ~2.7 KB
//! (54000), so either would fail the audit write *after* a write had run.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::audit::{AUDIT_SQL_MAX_BYTES, prefix_at_char_boundary};

/// Names: `server`, `database`, `schema`, `table`, a `request_id`. Twice
/// Postgres' 63-byte `NAMEDATALEN` limit, so no real name is refused.
const IDENTIFIER_MAX_BYTES: usize = 128;
/// A human-written justification, not a document.
const REASON_MAX_BYTES: usize = 1024;
/// The audit cap: every statement that runs is stored whole.
const SQL_MAX_BYTES: usize = AUDIT_SQL_MAX_BYTES;
/// Any other string argument (`since`, `cursor`).
const OTHER_MAX_BYTES: usize = 1024;
/// Argument names; every real one is a short identifier.
const KEY_MAX_BYTES: usize = 64;
/// Deserialisation errors can quote the offending value; keep the audit row
/// and client message short.
const PARSE_ERROR_MAX_BYTES: usize = 256;

const IDENTIFIER_KEYS: [&str; 5] = ["server", "database", "schema", "table", "request_id"];

/// What may appear in a string: identifiers take no control character at
/// all; free text keeps tab, newline and carriage return (multi-line SQL).
#[derive(Debug, Clone, Copy)]
enum Text {
    Identifier,
    Free,
}

/// `Err` names the argument and the rule it broke, never its value.
pub(super) fn check_arguments(arguments: &Value) -> Result<(), String> {
    match arguments {
        Value::Object(map) => check_object(map),
        Value::Null => Ok(()),
        _ => Err("`arguments` must be an object".to_owned()),
    }
}

fn check_object(map: &Map<String, Value>) -> Result<(), String> {
    for (key, value) in map {
        if key.len() > KEY_MAX_BYTES || has_forbidden_char(key, Text::Identifier) {
            return Err("an argument name is too long or contains a control character".into());
        }
        let (text, max) = rule_for(key);
        check_value(key, value, text, max)?;
    }
    Ok(())
}

fn check_value(key: &str, value: &Value, text: Text, max: usize) -> Result<(), String> {
    match value {
        Value::String(s) if s.len() > max => Err(format!("`{key}` exceeds {max} bytes")),
        Value::String(s) if has_forbidden_char(s, text) => {
            Err(format!("`{key}` contains a control character"))
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| check_value(key, item, text, max)),
        Value::Object(map) => check_object(map),
        _ => Ok(()),
    }
}

fn rule_for(key: &str) -> (Text, usize) {
    if IDENTIFIER_KEYS.contains(&key) {
        (Text::Identifier, IDENTIFIER_MAX_BYTES)
    } else if key == "sql" {
        (Text::Free, SQL_MAX_BYTES)
    } else if key == "reason" {
        (Text::Free, REASON_MAX_BYTES)
    } else {
        (Text::Free, OTHER_MAX_BYTES)
    }
}

fn has_forbidden_char(s: &str, text: Text) -> bool {
    s.chars().any(|c| match text {
        Text::Identifier => c.is_control(),
        Text::Free => c.is_control() && !matches!(c, '\t' | '\n' | '\r'),
    })
}

/// Deserialise a tool's arguments, or the client-facing reason they do not:
/// serde names the missing, mistyped or unknown field.
pub(super) fn parse_arguments<A: DeserializeOwned>(arguments: Option<Value>) -> Result<A, String> {
    let arguments = arguments.ok_or("`arguments` are required")?;
    serde_json::from_value(arguments).map_err(|err| {
        let message = format!("invalid arguments: {err}");
        prefix_at_char_boundary(&message, PARSE_ERROR_MAX_BYTES).to_owned()
    })
}

#[cfg(test)]
#[path = "args_tests.rs"]
mod tests;
