//! Random hammer: the guard must never panic, never allow a write-shaped
//! statement, and never crash on garbage input. Doesn't try to be a
//! complete grammar — just throws shapes at it. The token-soup properties
//! check the guard against Postgres's tokenization (`pg_scan`); the same
//! soup is run through a real Postgres in `tests/it_db/sql_guard_differential.rs`.

use super::*;
use proptest::prelude::*;

/// Pieces the two lexers are most likely to read differently: quotes,
/// escapes, string prefixes, comment openers, operator characters, line
/// breaks, dollar quotes, number shapes, non-ASCII.
const TOKEN_PIECES: &[&str] = &[
    " ", "\n", "\r", "\t", "'", "''", "\\", "\\'", "--", "/*", "*/", "$$", "$t$", "$1", "E'", "e'",
    "U&'", "U&\"", "X'", "B'", "N'", "b\"", "\"", ">", "<", "-", "/", "*", "|", "=", "@", "~", "+",
    "a", "1", "1e", ".", ",", "(", ")", ";", "::", "é", "\u{a0}", "0x", "L", "_",
];

fn token_soup() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(TOKEN_PIECES), 0..10)
        .prop_map(|pieces| pieces.concat())
}

/// A statement with a denied call the soup around it may hide or expose.
fn mutated_statement() -> impl Strategy<Value = String> {
    (token_soup(), token_soup(), token_soup())
        .prop_map(|(a, b, c)| format!("SELECT 1 {a} , pg_notify('c', 'p') {b} , lo_creat(1) {c}"))
}

/// `sql` as Postgres tokenizes it: comments dropped, one space between
/// tokens. Nothing is left for a second lexer to read another way.
fn as_postgres_tokens(sql: &str) -> Option<String> {
    let lexemes = pg_scan::scan(sql).ok()?;
    let texts: Vec<&str> = lexemes.iter().map(|l| &sql[l.start..l.end]).collect();
    Some(texts.join(" "))
}

fn is_one_read_statement(sql: &str) -> bool {
    let Ok(statements) = Parser::parse_sql(&PostgreSqlDialect {}, sql) else {
        return false;
    };
    let [statement] = statements.as_slice() else {
        return false;
    };
    let mut statement = statement;
    while let Statement::Explain {
        statement: inner, ..
    } = statement
    {
        statement = inner;
    }
    matches!(statement, Statement::Query(_))
}

fn arbitrary_safe_select() -> impl Strategy<Value = String> {
    proptest::sample::select(&[
        "SELECT 1",
        "SELECT id FROM t",
        "SELECT * FROM users WHERE id = 1",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "EXPLAIN SELECT 1",
        "EXPLAIN (FORMAT JSON) SELECT now()",
    ])
    .prop_map(|s| s.to_string())
}

fn arbitrary_write_or_ddl() -> impl Strategy<Value = String> {
    proptest::sample::select(&[
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET x = 1",
        "DELETE FROM t",
        "TRUNCATE t",
        "DROP TABLE t",
        "ALTER TABLE t ADD COLUMN y int",
        "CREATE TABLE t (id int)",
        "GRANT SELECT ON t TO bob",
        "REVOKE SELECT ON t FROM bob",
    ])
    .prop_map(|s| s.to_string())
}

fn arbitrary_denied_function() -> impl Strategy<Value = String> {
    proptest::sample::select(&[
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_read_binary_file('/etc/shadow')",
        "SELECT pg_ls_dir('/tmp')",
        "SELECT pg_stat_file('/etc/passwd')",
        "SELECT lo_export(1, '/tmp/x')",
        "SELECT lo_import('/etc/passwd')",
    ])
    .prop_map(|s| s.to_string())
}

/// What an admitted statement may be followed by: denied, however it is joined.
fn denied_continuation() -> impl Strategy<Value = String> {
    let join = proptest::sample::select(vec![
        " END, ",
        " end , ",
        "\nEND\n, ",
        " /* c */ END/**/,",
        " END + ",
        " END FROM ",
        " END; SELECT ",
        " ; END, ",
        ", ",
        " + ",
        " FROM ",
        " UNION SELECT ",
        " AND, ",
        " x, ",
        " AS end, ",
        " \"end\", ",
        " END WHERE ",
        " END ORDER BY ",
        " ORDER BY ",
        " LIMIT ",
        " OR ",
        " ",
    ]);
    let call = proptest::sample::select(vec![
        "pg_notify('c', 'p')",
        "pg_catalog.lo_creat(1)",
        "\"set_config\"('a.b', 'c', true)",
        "PG_LS_DIR('.')",
        "TREAT(1 AS pg_advisory_lock)",
        "cron.schedule('a', 'b')",
        "pg_stat_activity",
    ]);
    (join, call).prop_map(|(join, call)| format!("{join}{call}"))
}

fn arbitrary_write() -> impl Strategy<Value = String> {
    proptest::sample::select(vec![
        "INSERT INTO t VALUES (1)",
        "INSERT INTO t SELECT a FROM u RETURNING a",
        "UPDATE t SET x = 1 WHERE a",
        "DELETE FROM t WHERE a RETURNING x",
    ])
    .prop_map(str::to_string)
}

proptest! {
    /// No denied name that follows an admitted statement is ever admitted.
    #[test]
    fn a_denied_continuation_is_never_admitted(
        sql in prop_oneof![arbitrary_safe_select(), arbitrary_write()],
        soup in token_soup(),
        tail in denied_continuation(),
        more in prop_oneof![Just(""), Just(" END"), Just(" FROM t"), Just("; SELECT 1")],
    ) {
        for text in [format!("{sql}{tail}{more}"), format!("{sql}{soup}{tail}{more}")] {
            // The soup may put the call in a string or comment: judge the text
            // as Postgres tokenizes it.
            let plain = as_postgres_tokens(&text).unwrap_or_default().to_lowercase();
            let written = [
                "pg_notify (", "lo_creat (", "\"set_config\" (", "pg_ls_dir (", "treat (",
                "schedule (", "pg_stat_activity",
            ];
            if !written.iter().any(|call| plain.contains(call)) {
                continue;
            }
            for access in [Access::ReadOnly, Access::ReadWrite] {
                prop_assert!(check_sql(&text, access).is_err(), "{access:?}: {text:?}");
            }
        }
    }

    #[test]
    fn never_panics_on_arbitrary_strings(s in ".{0,200}") {
        // We don't care about the result — just that the parser path
        // never aborts. RecursionLimitExceeded is fine; it's a typed
        // GuardError::Parse, not a panic.
        let _ = is_read_only(&s);
    }

    #[test]
    fn never_panics_on_token_soup(sql in mutated_statement()) {
        let _ = check_sql(&sql, Access::ReadOnly);
        let _ = check_sql(&sql, Access::ReadWrite);
    }

    /// Whatever the read guard admits is still one admitted read statement
    /// once rewritten token by token the way Postgres splits it.
    #[test]
    fn admitted_text_is_one_read_statement_as_postgres_tokenizes_it(sql in token_soup()) {
        let sql = format!("SELECT 1 {sql}");
        if is_read_only(&sql).is_ok() {
            let plain = as_postgres_tokens(&sql);
            prop_assert!(plain.is_some(), "admitted but unscannable: {sql:?}");
            let plain = plain.unwrap_or_default();
            prop_assert!(is_one_read_statement(&plain), "{sql:?} reads as {plain:?}");
            prop_assert!(is_read_only(&plain).is_ok(), "{sql:?} reads as {plain:?}");
        }
    }

    /// No arrangement of quotes, comments and operators around a denied
    /// call gets it past the guard.
    #[test]
    fn token_mutations_never_hide_a_denied_call(sql in mutated_statement()) {
        if is_read_only(&sql).is_ok() {
            let plain = as_postgres_tokens(&sql).unwrap_or_default();
            prop_assert!(
                !plain.contains("pg_notify (") && !plain.contains("lo_creat ("),
                "{sql:?} reads as {plain:?}"
            );
        }
    }

    #[test]
    fn safe_selects_always_allowed(sql in arbitrary_safe_select()) {
        prop_assert!(is_read_only(&sql).is_ok(), "rejected: {sql}");
    }

    #[test]
    fn writes_always_rejected(sql in arbitrary_write_or_ddl()) {
        prop_assert!(
            matches!(is_read_only(&sql), Err(GuardError::NotAllowed(_))),
            "wrongly allowed: {sql}"
        );
    }

    /// Combining safe + unsafe via `;` always rejects on MultiStatement
    /// regardless of order — never short-circuits to "first one was OK".
    #[test]
    fn safe_then_unsafe_rejected(safe in arbitrary_safe_select(), unsafe_ in arbitrary_write_or_ddl()) {
        let combined = format!("{safe}; {unsafe_}");
        let got = is_read_only(&combined);
        prop_assert!(
            matches!(got, Err(GuardError::MultiStatement(_)) | Err(GuardError::NotAllowed(_)) | Err(GuardError::Parse(_))),
            "wrongly handled: `{combined}` → {got:?}"
        );
    }

    #[test]
    fn denied_functions_always_rejected(sql in arbitrary_denied_function()) {
        prop_assert!(
            matches!(is_read_only(&sql), Err(GuardError::DeniedFunction(_))),
            "wrongly allowed: {sql}"
        );
    }
}
