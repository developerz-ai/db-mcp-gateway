use super::*;

#[test]
fn the_name_at_the_error_position_is_kept_as_the_caller_spelled_it() {
    for (sqlstate, position, sql, want) in [
        (
            "42P01",
            15,
            "SELECT * FROM Usres",
            "relation does not exist: Usres",
        ),
        (
            "42P01",
            15,
            r#"SELECT * FROM "My ""T""".x WHERE true"#,
            r#"relation does not exist: "My ""T""".x"#,
        ),
        (
            "42P01",
            15,
            "SELECT * FROM nope.t, u",
            "relation does not exist: nope.t",
        ),
        ("42601", 10, "SELECT 1 FORM t", "syntax error: FORM"),
        (
            "42883",
            8,
            "SELECT nope(1)",
            "function or operator does not exist: nope",
        ),
        (
            "42703",
            8,
            "SELECT t.nöpe::int FROM t",
            "column does not exist: t.nöpe",
        ),
    ] {
        assert_eq!(rejection_message(sqlstate, Some(position), sql), want);
    }
}

#[test]
fn an_error_raised_over_row_data_names_nothing() {
    // The alias spells the very word a row could hold.
    let sql = "SELECT email::regclass AS alice FROM users";
    for sqlstate in [
        "3F000", "22P02", "22021", "23505", "P0001", "XX000", "55000",
    ] {
        for position in [None, Some(8), Some(26)] {
            let message = rejection_message(sqlstate, position, sql);
            assert_eq!(message, wording(sqlstate), "{sqlstate} at {position:?}");
        }
    }
    // A parser-class code without a position was raised at run time.
    for sqlstate in ["42P01", "42704", "42883", "42601", "42501"] {
        assert_eq!(rejection_message(sqlstate, None, sql), wording(sqlstate));
    }
}

#[test]
fn a_position_on_a_cast_names_nothing() {
    for (sql, position) in [
        ("SELECT email::regclass FROM users", 8),
        ("SELECT email :: regclass FROM users", 8),
        ("SELECT email::regclass FROM users", 13),
        ("SELECT CAST(email AS regclass) FROM users", 8),
        ("SELECT 'users'::regclass", 8),
    ] {
        let message = rejection_message("42P01", Some(position), sql);
        assert_eq!(message, "relation does not exist", "{sql} at {position}");
    }
}

#[test]
fn a_position_on_no_identifier_names_nothing() {
    for (sql, position) in [
        ("SELECT 1", 99),
        ("SELECT 1", 0),
        ("SELECT 1 2", 10),
        ("SELECT 1 + 'a'", 10),
        (r#"SELECT "unterminated"#, 8),
    ] {
        let message = rejection_message("42601", Some(position), sql);
        assert_eq!(message, "syntax error", "{sql} at {position}");
    }
    let long = format!("SELECT * FROM {}", "t".repeat(MAX_NAME_CHARS + 1));
    assert_eq!(
        rejection_message("42P01", Some(15), &long),
        "relation does not exist"
    );
}

#[test]
fn unlisted_codes_fall_back_to_class_then_generic_wording() {
    assert_eq!(wording("22999"), "data exception");
    assert_eq!(wording("P0999"), "error raised by a database function");
    assert_eq!(wording("F0000"), UNKNOWN);
    assert_eq!(wording(""), UNKNOWN);
}

#[test]
fn a_hint_passes_only_for_a_located_parser_diagnostic_off_a_cast() {
    let hint = Some("No function matches the given name and argument types.");
    let sql = "SELECT emial FROM users";
    assert_eq!(safe_hint("42883", Some(8), sql, hint), hint);
    // A column hint can name a column outside the role's column grants.
    let column = Some("Perhaps you meant to reference the column \"users.email\".");
    assert_eq!(safe_hint("42703", Some(8), sql, column), None);
    assert_eq!(safe_hint("42702", Some(8), sql, column), None);
    // A syntax error located on no identifier still keeps its hint.
    assert_eq!(safe_hint("42601", Some(10), "SELECT 1 2", hint), hint);
    // Raised at run time (no position), or outside class 42: dropped.
    assert_eq!(safe_hint("42883", None, sql, hint), None);
    assert_eq!(safe_hint("22P02", Some(8), sql, hint), None);
    assert_eq!(safe_hint("P0001", Some(8), sql, hint), None);
    // On a cast operand the lookup ran over row data.
    let cast = "SELECT email::regclass FROM users";
    assert_eq!(safe_hint("42P01", Some(8), cast, hint), None);
    assert_eq!(safe_hint("42601", Some(10), "SELECT 1 2", None), None);
}
