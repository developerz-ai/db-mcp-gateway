use super::*;

// --- Lexical differentials: text Postgres reads differently from sqlparser ---

/// Postgres reads `U&"\0070g_notify"` as one Unicode-escaped identifier,
/// `pg_notify`; sqlparser reads `U & "\0070g_notify"(…)`, a bitwise AND with
/// a call to a function literally named `\0070g_notify`. The denylist never
/// sees the real name, so the form is refused outright.
#[test]
fn unicode_escaped_identifiers_rejected() {
    for sql in [
        r#"select U&"\0070g_notify"('ch', 'x')"#,
        r#"select u&"\0070g_advisory_lock"(42)"#,
        r#"select U&"\0073et_config"('work_mem', '1GB', false)"#,
        r#"select U&"\0070g_terminate_backend"(1)"#,
        r#"select * from U&"\0070g_ls_dir"('.')"#,
        r#"select U&"pg_notify"('a', 'b')"#,
        r#"select U&"col" from t"#,
        r#"select * from U&"t""#,
        r#"EXPLAIN ANALYZE select U&"\0070g_notify"('ch', 'x')"#,
        r#"EXPLAIN select U&"\0070g_notify"('ch', 'x')"#,
    ] {
        rejected(sql, GuardError::UnicodeEscapedIdentifier);
    }
}

#[test]
fn unicode_escaped_identifiers_rejected_in_write_mode() {
    let sql = r#"UPDATE t SET a = U&"\0070g_notify"('c', 'p')"#;
    assert_eq!(
        check_sql(sql, Access::ReadWrite),
        Err(GuardError::UnicodeEscapedIdentifier)
    );
}

/// With whitespace around `&` Postgres reads a plain bitwise AND too, so both
/// sides agree; Unicode-escaped *strings* are decoded by sqlparser itself.
#[test]
fn bitwise_and_and_unicode_strings_still_allowed() {
    ok(r#"select u & "x" from t"#);
    ok("select a&b from t");
    ok(r#"select a&"b" from t"#);
    ok(r"select U&'\0070g' from t");
}

/// `UESCAPE` changes the escape character; sqlparser does not parse it.
#[test]
fn uescape_rejected() {
    assert_eq!(
        is_read_only(r#"select U&"!0070g_notify" UESCAPE '!' ('a', 'b')"#),
        Err(GuardError::UnicodeEscapedIdentifier)
    );
    assert_eq!(
        is_read_only(r"select U&'!0070' UESCAPE '!'"),
        Err(GuardError::Parse)
    );
}

/// Other spellings of a denied name already reach the denylist: quoting,
/// schema qualification (quoted or spaced), and Postgres-nested comments.
#[test]
fn other_spellings_of_a_denied_name_are_caught() {
    for sql in [
        r#"select "pg_notify"('a', 'b')"#,
        r#"select "PG_NOTIFY"('a', 'b')"#,
        r#"select "pg_catalog"."pg_notify"('a', 'b')"#,
        "select pg_catalog . pg_notify('a', 'b')",
        "select pg_notify\n('a', 'b')",
        r"select '\', pg_notify('a', 'b') --'",
        "select $q$ $$ $q$, pg_notify('a', 'b')",
        "select 1 /* /* */ */ , pg_notify('a', 'b')",
    ] {
        match is_read_only(sql) {
            Err(GuardError::DeniedFunction("pg_notify")) => {}
            other => panic!("expected pg_notify denied for `{sql}`, got {other:?}"),
        }
    }
}

/// The refusal names the problem and the fix, not a statement type: the
/// statement itself is usually a perfectly allowed SELECT.
#[test]
fn unicode_escape_message_tells_the_agent_to_spell_it_plainly() {
    let msg = is_read_only(r#"select U&"col" from t"#)
        .expect_err("refused")
        .to_string();
    assert!(msg.contains("spell the identifier plainly"), "{msg}");
    assert!(!msg.contains("statement type"), "{msg}");
}
