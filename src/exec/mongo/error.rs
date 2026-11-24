//! The text kept for a command the Mongo server refused.
//!
//! The server's `errmsg` echoes the command — filter values included — and,
//! for an error raised while documents were read, values from those
//! documents. So, as on Postgres (`pg/redact.rs`), the sentence is the
//! gateway's, keyed by the server's error code, and the one name added is a
//! field name or operator the caller's own command spells as a key, kept
//! only for codes the server raises while parsing the command, before any
//! document is read.

use serde_json::Value;

use super::super::rejection::DbRejection;

/// Wording for one server error code; anything else gets [`UNKNOWN`].
const BY_CODE: &[(i32, &str)] = &[
    (2, "bad value in the command"),
    (9, "the command could not be parsed"),
    (14, "type mismatch"),
    (26, "namespace does not exist"),
    (72, "invalid command option"),
    (96, "operation failed"),
    (168, "unrecognized expression operator"),
    (241, "value conversion failed"),
    (292, "query exceeded its memory limit; set allowDiskUse"),
    (15998, "invalid field path"),
    (16410, "field path must not start with `$`"),
    (31249, "projection path collision"),
    (31250, "projection path collision"),
    (31325, "unrecognized expression operator"),
    (40323, "a pipeline stage must hold exactly one field"),
    (40324, "unrecognized pipeline stage"),
    (51091, "invalid regular expression"),
];

const UNKNOWN: &str = "command rejected by the database";

/// Codes raised while the server parses the command: their `errmsg` quotes
/// the command, never a document.
const PARSE_CODES: &[i32] = &[2, 9, 168, 15998, 16410, 31249, 31250, 31325, 40323, 40324];

/// Longest name kept; a longer one is not named at all.
const MAX_NAME_CHARS: usize = 128;

/// A refused command as the agent and the audit row see it: the code, the
/// gateway's wording and at most one name from `command` (the caller's JSON).
pub(super) fn command_rejection(code: i32, errmsg: &str, command: &str) -> DbRejection {
    let wording = BY_CODE
        .iter()
        .find(|(known, _)| *known == code)
        .map_or(UNKNOWN, |(_, text)| *text);
    let name = PARSE_CODES
        .contains(&code)
        .then(|| key_named_in(errmsg, command))
        .flatten();
    let message = match name {
        Some(name) => format!("{wording}: {name}"),
        None => wording.to_string(),
    };
    DbRejection::new(&code.to_string(), &message, "")
}

/// The key of `command` that `errmsg` names last, as a whole word: the
/// server words a nested error outermost first (`Invalid $project :: caused
/// by :: Unrecognized expression '$fooo'`).
fn key_named_in(errmsg: &str, command: &str) -> Option<String> {
    let value: Value = serde_json::from_str(command).ok()?;
    let mut keys = Vec::new();
    collect_keys(&value, &mut keys);
    errmsg
        .split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '$' | '.' | '-')))
        .rev()
        .filter(|word| !word.is_empty() && word.chars().count() <= MAX_NAME_CHARS)
        .find(|word| keys.contains(word))
        .map(str::to_owned)
}

fn collect_keys<'v>(value: &'v Value, keys: &mut Vec<&'v str>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                keys.push(key);
                collect_keys(child, keys);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_keys(item, keys)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parse_error_names_the_callers_key_never_a_value() {
        let command = r#"{"aggregate":"orders","pipeline":[{"$match":{"email":"alice@example.com"}},{"$project":{"x":{"$fooo":"$email"}}}],"cursor":{}}"#;
        let r = command_rejection(
            168,
            "Invalid $project :: caused by :: Unrecognized expression '$fooo'",
            command,
        );
        assert_eq!(r.sqlstate(), "168");
        assert_eq!(r.message(), "unrecognized expression operator: $fooo");

        let r = command_rejection(
            2,
            "unknown operator: $eqq in alice@example.com",
            r#"{"find":"u","filter":{"email":{"$eqq":"alice@example.com"}}}"#,
        );
        assert_eq!(r.message(), "bad value in the command: $eqq");
    }

    #[test]
    fn a_run_time_error_names_nothing() {
        // The document's value is spelled as a key in the command too.
        let command = r#"{"aggregate":"u","pipeline":[{"$project":{"abc":{"$toInt":"$v"}}}]}"#;
        let r = command_rejection(241, "Failed to parse number 'abc' in $convert", command);
        assert_eq!(r.message(), "value conversion failed");
        let r = command_rejection(99_999, "something about abc", command);
        assert_eq!(r.message(), UNKNOWN);
        assert_eq!(r.sqlstate(), "99999");
    }

    #[test]
    fn no_key_in_the_message_names_nothing() {
        let r = command_rejection(9, "BSON field 'x' is missing", r#"{"find":"u"}"#);
        assert_eq!(r.message(), "the command could not be parsed");
    }
}
