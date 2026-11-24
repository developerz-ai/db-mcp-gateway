//! The text kept for a statement the target refused.
//!
//! The server's own message is never passed on. It can carry row data in
//! any position — quoted (`relation "alice@example.com" does not exist`,
//! from a column cast to `regclass`), unquoted (the bytes of an encoding
//! error, the text of a `RAISE EXCEPTION`) — and what is kept here is what
//! the agent reads *and* what the audit row and its sinks store. So the
//! sentence is the gateway's, chosen by SQLSTATE, and the only server text
//! that survives is a name the caller's own statement already spells: a
//! typo'd table is still named, a value read from a row never is.

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

/// Most names appended to one message, and the longest one kept.
const MAX_NAMES: usize = 4;
const MAX_NAME_CHARS: usize = 128;

fn wording(sqlstate: &str) -> &'static str {
    let lookup = |table: &[(&str, &'static str)], key: &str| {
        table.iter().find(|(k, _)| *k == key).map(|(_, text)| *text)
    };
    lookup(BY_SQLSTATE, sqlstate)
        .or_else(|| lookup(BY_CLASS, sqlstate.get(..2).unwrap_or(sqlstate)))
        .unwrap_or(UNKNOWN)
}

/// The message for `sqlstate`: the gateway's wording, then the names from
/// `server_message` that `sql` itself spells — `relation does not exist:
/// "usres"`. `position` is the server's 1-based character offset into `sql`;
/// the word there is the caller's own text, so it is named too.
pub(super) fn rejection_message(
    sqlstate: &str,
    server_message: &str,
    position: Option<usize>,
    sql: &str,
) -> String {
    let sql_lower = sql.to_lowercase();
    let mut names: Vec<String> = Vec::new();
    let candidates = quoted_segments(server_message)
        .chain(denied_object(sqlstate, server_message))
        .filter(|name| spelled_in(&sql_lower, name))
        .map(str::to_string)
        .chain(position.and_then(|at| word_at(sql, at)));
    for name in candidates {
        let seen = names.iter().any(|kept| kept.eq_ignore_ascii_case(&name));
        if !seen && names.len() < MAX_NAMES {
            names.push(name);
        }
    }
    let text = wording(sqlstate);
    if names.is_empty() {
        return text.to_string();
    }
    let quoted: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
    format!("{text}: {}", quoted.join(", "))
}

/// What sits between each pair of double quotes. Postgres does not escape a
/// quote inside a quoted value, so a pairing can be wrong; every segment is
/// checked against the statement before it is kept, so a wrong pairing can
/// only drop a name.
fn quoted_segments(message: &str) -> impl Iterator<Item = &str> {
    message.split('"').skip(1).step_by(2)
}

/// `permission denied for table users` names its object unquoted, as the
/// last word.
fn denied_object<'m>(sqlstate: &str, message: &'m str) -> Option<&'m str> {
    (sqlstate == "42501")
        .then(|| message.rsplit(' ').next())
        .flatten()
}

/// Whether the statement contains `name` as a whole word. Case-folded, as
/// Postgres folds an unquoted identifier before reporting it.
fn spelled_in(sql_lower: &str, name: &str) -> bool {
    let needle = name.to_lowercase();
    if needle.is_empty() || needle.chars().count() > MAX_NAME_CHARS {
        return false;
    }
    let joins = |outside: Option<char>, edge: Option<char>| {
        outside.is_some_and(is_word_char) && edge.is_some_and(is_word_char)
    };
    sql_lower.match_indices(&needle).any(|(at, found)| {
        let before = sql_lower[..at].chars().next_back();
        let after = sql_lower[at + found.len()..].chars().next();
        !joins(before, needle.chars().next()) && !joins(after, needle.chars().next_back())
    })
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The (possibly qualified) name starting at the 1-based character offset
/// `position` of `sql`, if one starts there.
fn word_at(sql: &str, position: usize) -> Option<String> {
    let word: String = sql
        .chars()
        .skip(position.checked_sub(1)?)
        .take_while(|c| is_word_char(*c) || matches!(c, '.' | '$'))
        .take(MAX_NAME_CHARS)
        .collect();
    (!word.is_empty()).then_some(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_the_statement_spells_is_kept() {
        assert_eq!(
            rejection_message(
                "42P01",
                r#"relation "usres" does not exist"#,
                Some(15),
                "SELECT * FROM Usres"
            ),
            r#"relation does not exist: "usres""#
        );
        assert_eq!(
            rejection_message(
                "42601",
                r#"syntax error at or near "FORM""#,
                Some(10),
                "SELECT 1 FORM t"
            ),
            r#"syntax error: "FORM""#
        );
    }

    #[test]
    fn a_value_read_from_a_row_is_not() {
        let sql = "SELECT email::regclass FROM users";
        for (sqlstate, server) in [
            ("42P01", r#"relation "alice@example.com" does not exist"#),
            ("42704", r#"type "alice@example.com" does not exist"#),
            ("3F000", r#"schema "alice@example.com" does not exist"#),
            (
                "22P02",
                r#"invalid input syntax for type integer: "alice@example.com""#,
            ),
            (
                "22021",
                r#"invalid byte sequence for encoding "UTF8": 0xe9 0x61 0x6c"#,
            ),
            ("P0001", "refusing row alice@example.com"),
            ("XX000", "unexpected alice@example.com"),
        ] {
            let message = rejection_message(sqlstate, server, None, sql);
            assert!(!message.contains("alice"), "{sqlstate}: {message}");
            assert!(!message.contains("0xe9"), "{sqlstate}: {message}");
            assert!(!message.contains('"'), "{sqlstate}: {message}");
        }
    }

    #[test]
    fn a_row_value_is_not_kept_for_being_part_of_a_longer_word() {
        let message = rejection_message(
            "42P01",
            r#"relation "user" does not exist"#,
            None,
            "SELECT name::regclass FROM users",
        );
        assert_eq!(message, "relation does not exist");
    }

    #[test]
    fn the_word_at_the_error_position_is_named() {
        assert_eq!(
            rejection_message(
                "42883",
                "function nope(integer) does not exist",
                Some(8),
                "SELECT nope(1)"
            ),
            r#"function or operator does not exist: "nope""#
        );
        // A position past the end, or on punctuation, names nothing.
        assert_eq!(word_at("SELECT 1", 99), None);
        assert_eq!(word_at("SELECT 'a'::int", 8), None);
        assert_eq!(word_at("SELECT 1", 0), None);
    }

    #[test]
    fn a_denied_object_is_named_when_the_statement_spells_it() {
        let server = "permission denied for table accounts";
        assert_eq!(
            rejection_message("42501", server, None, "SELECT * FROM accounts"),
            r#"permission denied: "accounts""#
        );
        assert_eq!(
            rejection_message("42501", server, None, "SELECT f()"),
            "permission denied"
        );
    }

    #[test]
    fn unlisted_codes_fall_back_to_class_then_generic_wording() {
        assert_eq!(wording("22999"), "data exception");
        assert_eq!(wording("P0999"), "error raised by a database function");
        assert_eq!(wording("F0000"), UNKNOWN);
        assert_eq!(wording(""), UNKNOWN);
    }
}
