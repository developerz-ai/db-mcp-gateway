//! The SQL guard held against Postgres's own parser. The guard decides on
//! sqlparser's reading of the text; the target runs Postgres's. Here the
//! target stores each statement in a view and prints it back
//! (`pg_get_viewdef`) — its reading, with every call spelled `name(args)` —
//! without executing it. Whatever the guard admits must call only names the
//! guard saw as words, and must still be admitted in Postgres's spelling.

use std::collections::BTreeSet;
use std::ops::ControlFlow;

use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;
use sqlparser::ast::{Expr, visit_expressions};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};
use sqlx::{Connection, PgConnection};

use crate::common::pg_target::{is_yugabyte, owner_url};
use db_mcp_gateway::exec::sql_guard::is_read_only;

/// The wrapper's own aggregate, the one call the corpus did not write.
const WRAPPER_CALL: &str = "count";

/// `sql` as the target parses it, or `None` when it rejects the text — then
/// nothing would have run. One prepared statement, rolled back: the text
/// can neither execute nor smuggle a second statement in.
async fn as_postgres_reads(conn: &mut PgConnection, sql: &str) -> Option<String> {
    let mut tx = conn.begin().await.expect("transaction opens");
    let view = format!("CREATE TEMP VIEW dbmcp_reading AS SELECT count(*) FROM ({sql}\n) t");
    let created = sqlx::query(&view).persistent(false).execute(&mut *tx).await;
    let reading = match created {
        Ok(_) => Some(
            sqlx::query_scalar::<_, String>("SELECT pg_get_viewdef('dbmcp_reading'::regclass)")
                .fetch_one(&mut *tx)
                .await
                .expect("view definition reads back"),
        ),
        Err(_) => None,
    };
    tx.rollback().await.expect("rollback");
    reading
}

/// Every function Postgres's printed statement calls, lower-cased.
fn calls(reading: &str) -> BTreeSet<String> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, reading)
        .unwrap_or_else(|err| panic!("Postgres's own spelling parses: {err}\n{reading}"));
    let mut names = BTreeSet::new();
    let _ = visit_expressions(&statements, |expr| {
        if let Expr::Function(f) = expr
            && let Some(name) = f.name.0.last().and_then(|part| part.as_ident())
        {
            names.insert(name.value.to_ascii_lowercase());
        }
        ControlFlow::<()>::Continue(())
    });
    names
}

/// Every word the guard's lexer saw in `sql`, lower-cased: the names it
/// could have checked.
fn words(sql: &str) -> BTreeSet<String> {
    Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize()
        .expect("admitted text tokenizes")
        .into_iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.value.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// The property, for one admitted statement the target also accepts.
fn assert_same_reading(sql: &str, reading: &str) {
    let seen = words(sql);
    let unseen: Vec<String> = calls(reading)
        .into_iter()
        .filter(|name| name != WRAPPER_CALL && !seen.contains(name))
        .collect();
    assert!(
        unseen.is_empty(),
        "admitted {sql:?}, but Postgres calls {unseen:?} the guard never saw:\n{reading}"
    );
    assert_eq!(
        is_read_only(reading),
        Ok(()),
        "admitted {sql:?}, refused as Postgres spells it:\n{reading}"
    );
}

async fn connect() -> PgConnection {
    PgConnection::connect(&owner_url())
        .await
        .expect("target connects")
}

/// Statements the guard must refuse, with the call Postgres finds in each —
/// proof the reading the guard would have trusted is not the target's.
const HIDDEN_CALLS: &[(&str, &str)] = &[
    // Postgres ends the operator at `--`; the next line is code.
    ("SELECT 1 >--'\n 2, md5($$x$$)--'", "md5"),
    (
        "SELECT 1 <--'\n 2, pg_notify($$jobs$$, $$x$$)--'",
        "pg_notify",
    ),
    // The continuation line keeps the first literal's backslash escapes.
    ("SELECT E'a'\n'\\' , ' , md5($$x$$) -- '", "md5"),
    (
        "SELECT E'a'\n'\\' , ' , pg_notify($$j$$, $$x$$) -- '",
        "pg_notify",
    ),
    // Attribute notation is a call.
    (
        "SELECT (pid).pg_cancel_backend FROM pg_locks",
        "pg_cancel_backend",
    ),
    ("SELECT (1).lo_creat", "lo_creat"),
    (r#"SELECT U&"\0070g_backend_pid"()"#, "pg_backend_pid"),
];

#[tokio::test]
#[serial_test::parallel(world)]
async fn refused_spellings_hide_a_call_postgres_would_make() {
    let mut conn = connect().await;
    for (sql, hidden) in HIDDEN_CALLS {
        assert!(is_read_only(sql).is_err(), "must be refused: {sql:?}");
        let reading = as_postgres_reads(&mut conn, sql)
            .await
            .unwrap_or_else(|| panic!("the target accepts {sql:?}"));
        assert!(
            calls(&reading).contains(*hidden),
            "{sql:?} should call {hidden}:\n{reading}"
        );
    }
}

/// Statements the guard must keep admitting; the target reads each the way
/// the guard does.
const ADMITTED: &[&str] = &[
    "SELECT 1 > -- c\n 2",
    "SELECT relname-- c\n FROM pg_class",
    "SELECT 'a' ||\n 'b',\n 'c'",
    "SELECT 'a', -- md5('x')\n 'b'",
    "SELECT E'it\\'s', e'\\\\', B'101', X'1F', U&'\\0041'",
    "SELECT $$ it's -- md5('x') $$, $q$ $$ md5('x') $q$",
    "SELECT /* a /* md5('x') */ b */ upper('x') -- md5('x')",
    "SELECT upper('a'), ('a'::text).upper, c.row_to_json FROM pg_class c",
    "SELECT 1 - -1, 1e5, 1.5e-3, .5, 2 * 3 / 4",
    "SELECT '{\"a\":1}'::jsonb ->> 'a', '{}'::jsonb @> '{}'::jsonb",
    "SELECT \"relname\", c.\"oid\" FROM pg_catalog.\"pg_class\" c WHERE relname = 'pg_stat_activity'",
];

#[tokio::test]
#[serial_test::parallel(world)]
async fn admitted_statements_read_the_same_to_postgres() {
    let mut conn = connect().await;
    for sql in ADMITTED {
        assert_eq!(is_read_only(sql), Ok(()), "must stay admitted: {sql:?}");
        let reading = as_postgres_reads(&mut conn, sql)
            .await
            .unwrap_or_else(|| panic!("the target accepts {sql:?}"));
        assert_same_reading(sql, &reading);
    }
}

/// The pieces `sql_guard::proptests` mutates with: where two lexers are
/// most likely to part ways.
const TOKEN_PIECES: &[&str] = &[
    " ", "\n", "\r", "\t", "'", "''", "\\", "\\'", "--", "/*", "*/", "$$", "$t$", "E'", "e'",
    "U&'", "X'", "B'", "N'", "b\"", "\"", ">", "<", "-", "/", "*", "|", "=", "@", "~", "+", "a",
    "1", "1e", ".", ",", "(", ")", "::", "é", "0x", "L", "_",
];

fn token_soup() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(TOKEN_PIECES), 0..8)
        .prop_map(|pieces| pieces.concat())
}

/// Mutated statements around calls — harmless ones, then one denied — that
/// the mutation may move into or out of a string or comment. Every
/// statement the guard admits and the target accepts must read the same to
/// both. Deterministic, so a failure reproduces.
#[tokio::test]
#[serial_test::parallel(world)]
async fn token_mutations_read_the_same_to_postgres() {
    // Each case is a DDL round trip, which YugabyteDB makes slow.
    let cases = if is_yugabyte() { 300 } else { 4000 };
    let strategy = (token_soup(), token_soup(), token_soup());
    let mut runner = TestRunner::deterministic();
    let mut conn = connect().await;
    let mut compared = 0;
    for _ in 0..cases {
        let (a, b, c) = strategy
            .new_tree(&mut runner)
            .expect("strategy generates")
            .current();
        for sql in [
            format!("SELECT 1 {a} , md5('p') {b} , upper('q') {c}"),
            format!("SELECT 1 {a} , md5('p') {b} , pg_notify('c', 'p') {c}"),
        ] {
            if is_read_only(&sql).is_err() {
                continue;
            }
            if let Some(reading) = as_postgres_reads(&mut conn, &sql).await {
                assert_same_reading(&sql, &reading);
                compared += 1;
            }
        }
    }
    assert!(
        compared >= cases / 100,
        "only {compared} of {cases} mutations reached the comparison"
    );
}
