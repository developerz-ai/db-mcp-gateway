//! The text kept for a statement the target refused.
//!
//! The server's own message is never read. It can carry row data in any
//! position — quoted (`relation "alice@example.com" does not exist`, from a
//! column cast to `regclass`), unquoted (the bytes of an encoding error, the
//! text of a `RAISE EXCEPTION`) — and what is kept here is what the agent
//! reads *and* what the audit row and its sinks store. Even keeping only
//! the server words the statement also spells would answer "does a row hold
//! this text?". So the sentence is the gateway's, chosen by SQLSTATE, and
//! the one name added is cut out of the submitted SQL at the offset the
//! parser reported: a typo'd table is still named, in the caller's own
//! spelling, and an error raised while rows were being read names nothing.

/// Wording for one SQLSTATE; anything not listed falls back to its class.
const BY_SQLSTATE: &[(&str, &str)] = &[
    ("0A000", "feature not supported"),
    ("21000", "subquery returned more than one row"),
    ("22001", "value too long for the target type"),
    ("22003", "numeric value out of range"),
    ("22004", "null value not allowed"),
    ("22007", "invalid date/time format"),
    ("22008", "date/time field value out of range"),
    ("22012", "division by zero"),
    ("2201B", "invalid regular expression"),
    ("22021", "invalid byte sequence for the encoding"),
    ("22023", "invalid parameter value"),
    ("22032", "invalid JSON text"),
    ("22P02", "invalid input syntax for the target type"),
    ("22P03", "invalid binary representation"),
    ("22P05", "character cannot be converted between encodings"),
    ("23502", "null value violates a not-null constraint"),
    ("23503", "foreign key constraint violated"),
    ("23505", "unique constraint violated"),
    ("23514", "check constraint violated"),
    ("23P01", "exclusion constraint violated"),
    ("25006", "cannot write in a read-only transaction"),
    ("25P02", "transaction is aborted"),
    ("3D000", "database does not exist"),
    ("3F000", "schema does not exist"),
    ("40001", "could not serialize access; retry the statement"),
    ("40P01", "deadlock detected"),
    ("42501", "permission denied"),
    ("42601", "syntax error"),
    ("42602", "invalid name"),
    ("42701", "column specified more than once"),
    ("42702", "column reference is ambiguous"),
    ("42703", "column does not exist"),
    ("42704", "object does not exist"),
    ("42712", "table name specified more than once"),
    ("42725", "function or operator is not unique"),
    ("42803", "column must appear in GROUP BY or an aggregate"),
    ("42804", "datatype mismatch"),
    ("42846", "cannot cast between these types"),
    ("42883", "function or operator does not exist"),
    ("42P01", "relation does not exist"),
    ("42P02", "parameter does not exist"),
    ("42P18", "could not determine a data type"),
    ("54001", "statement too complex"),
    ("55P03", "lock not available"),
    ("P0001", "raised by a database function or trigger"),
    ("P0002", "query returned no rows"),
    ("P0003", "query returned more than one row"),
    ("P0004", "assertion failed in a database function"),
];

/// Wording for a SQLSTATE class (its first two characters).
const BY_CLASS: &[(&str, &str)] = &[
    ("22", "data exception"),
    ("23", "integrity constraint violated"),
    ("25", "invalid transaction state"),
    ("40", "transaction rolled back"),
    ("42", "syntax error or access rule violation"),
    ("54", "program limit exceeded"),
    ("55", "object not in the required state"),
    ("P0", "error raised by a database function"),
    ("XX", "internal error in the database server"),
];

const UNKNOWN: &str = "statement rejected by the database";

/// Longest name kept; a longer one is not named at all.
const MAX_NAME_CHARS: usize = 128;

fn wording(sqlstate: &str) -> &'static str {
    let lookup = |table: &[(&str, &'static str)], key: &str| {
        table.iter().find(|(k, _)| *k == key).map(|(_, text)| *text)
    };
    lookup(BY_SQLSTATE, sqlstate)
        .or_else(|| lookup(BY_CLASS, sqlstate.get(..2).unwrap_or(sqlstate)))
        .unwrap_or(UNKNOWN)
}

/// The message for `sqlstate`: the gateway's wording, then — for a parse or
/// analysis diagnostic only — the identifier `sql` holds at `position`, the
/// server's 1-based character offset into it: `relation does not exist:
/// Usres`.
pub(super) fn rejection_message(sqlstate: &str, position: Option<usize>, sql: &str) -> String {
    let text = wording(sqlstate);
    let name = position
        .filter(|_| is_parser_diagnostic(sqlstate))
        .and_then(|at| name_at(sqlstate, sql, at));
    match name {
        Some(name) => format!("{text}: {name}"),
        None => text.to_string(),
    }
}

/// Class `42` (syntax error or access rule violation) is where the parser
/// and the analyser report a name they took from the statement. Every other
/// class is raised while the statement runs, over data.
fn is_parser_diagnostic(sqlstate: &str) -> bool {
    sqlstate.starts_with("42")
}

/// SQLSTATEs raised only while resolving a column reference, which a
/// catalog lookup over row data (`col::regclass`) never raises.
const COLUMN_REFERENCE: &[&str] = &["42702", "42703"];

/// The identifier the caller typed at `position`, unless it is the operand
/// of a cast: `email::regclass` looks its relation up from row data, so a
/// position on that expression points at no name the caller chose.
pub(super) fn name_at<'s>(sqlstate: &str, sql: &'s str, position: usize) -> Option<&'s str> {
    let (name, after) = identifier_at(sql, position)?;
    let named = !is_cast(name, after) || COLUMN_REFERENCE.contains(&sqlstate);
    (named && name.chars().count() <= MAX_NAME_CHARS).then_some(name)
}

/// The server's hint, when it can only be about the statement: a parse or
/// analysis diagnostic (class `42`) located in the caller's statement, not
/// on a cast operand. Those hints name statement objects and fixed advice
/// (`No function matches the given name and argument types.`); a hint
/// raised at run time, over data, has no position and is dropped. A column
/// diagnostic's hint is dropped too: Postgres picks the column it suggests
/// from the whole relation, column grants aside — `near_misses` is the
/// privilege-filtered answer.
pub(super) fn safe_hint<'h>(
    sqlstate: &str,
    position: Option<usize>,
    sql: &str,
    hint: Option<&'h str>,
) -> Option<&'h str> {
    if COLUMN_REFERENCE.contains(&sqlstate) {
        return None;
    }
    let at = position.filter(|_| is_parser_diagnostic(sqlstate))?;
    let on_cast = identifier_at(sql, at).is_some_and(|(name, after)| is_cast(name, after));
    if on_cast { None } else { hint }
}

/// The (possibly qualified) identifier starting at the 1-based character
/// `position`, and the text after it.
fn identifier_at(sql: &str, position: usize) -> Option<(&str, &str)> {
    let (start, _) = sql.char_indices().nth(position.checked_sub(1)?)?;
    let rest = &sql[start..];
    let mut len = part_len(rest)?;
    while let Some(next) = rest[len..].strip_prefix('.').and_then(part_len) {
        len += 1 + next;
    }
    Some(rest.split_at(len))
}

fn is_cast(name: &str, after: &str) -> bool {
    name.eq_ignore_ascii_case("cast") || after.trim_start().starts_with("::")
}

/// Byte length of the identifier `text` starts with — bare, or double-quoted
/// with `""` for a quote inside — if it starts with one.
fn part_len(text: &str) -> Option<usize> {
    let Some(quoted) = text.strip_prefix('"') else {
        let first = text.chars().next()?;
        let bare = |c: char| c.is_alphanumeric() || matches!(c, '_' | '$');
        return (first.is_alphabetic() || first == '_')
            .then(|| text.find(|c| !bare(c)).unwrap_or(text.len()));
    };
    let mut quotes = quoted.match_indices('"').map(|(at, _)| at).peekable();
    while let Some(at) = quotes.next() {
        // `""` is one escaped quote, not the end.
        if quotes.next_if_eq(&(at + 1)).is_none() {
            return Some(at + 2);
        }
    }
    None
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "redact_proptests.rs"]
mod proptests;
