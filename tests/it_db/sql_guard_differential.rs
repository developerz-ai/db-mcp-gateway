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
use sqlparser::ast::{
    Expr, ObjectName, SelectItem, SetExpr, Statement, TableFactor, Visit, Visitor,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};
use sqlx::{Column, Connection, Executor, PgConnection, SqlSafeStr, Statement as _};

use crate::common::pg_target::{is_yugabyte, owner_url};
use db_mcp_gateway::exec::sql_guard::{GuardError, is_read_only};

/// The wrapper's own aggregate, the one call the corpus did not write.
const WRAPPER_CALL: &str = "count";

/// `sql` as the target parses it, or `None` when it rejects the text — then
/// nothing would have run. One prepared statement, rolled back: the text
/// can neither execute nor smuggle a second statement in.
async fn as_postgres_reads(conn: &mut PgConnection, sql: &str) -> Option<String> {
    let mut tx = conn.begin().await.expect("transaction opens");
    let view = format!("CREATE TEMP VIEW dbmcp_reading AS SELECT count(*) FROM ({sql}\n) t");
    let created = sqlx::query(sqlx::AssertSqlSafe(view))
        .persistent(false)
        .execute(&mut *tx)
        .await;
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

/// Every function Postgres's printed statement calls, lower-cased — in an
/// expression or as a table source (`FROM generate_series(1, 3)`).
fn calls(reading: &str) -> BTreeSet<String> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, reading)
        .unwrap_or_else(|err| panic!("Postgres's own spelling parses: {err}\n{reading}"));
    let mut collector = CallCollector::default();
    let _ = statements.visit(&mut collector);
    collector.names
}

#[derive(Default)]
struct CallCollector {
    names: BTreeSet<String>,
}

impl CallCollector {
    fn insert(&mut self, name: &ObjectName) {
        if let Some(ident) = name.0.last().and_then(|part| part.as_ident()) {
            self.names.insert(ident.value.to_ascii_lowercase());
        }
    }
}

impl Visitor for CallCollector {
    type Break = ();

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        if let Expr::Function(f) = expr {
            self.insert(&f.name);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<()> {
        match tf {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            }
            | TableFactor::Function { name, .. } => self.insert(name),
            _ => {}
        }
        ControlFlow::Continue(())
    }
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
    "SELECT * FROM generate_series(1, 3)",
    "SELECT g FROM generate_series(1, 3) AS g, LATERAL unnest(ARRAY[g]) u",
    // Calls sqlparser models as their own expressions or table factors and
    // Postgres's grammar writes as plain calls: the second parser agrees.
    "SELECT ceil(1.5), ceiling(1.5), floor(1.5), substring('abc', 1, 2)",
    "SELECT * FROM unnest(ARRAY[1, 2]) WITH ORDINALITY",
    "SELECT extract(year FROM now()), now() AT TIME ZONE 'UTC', trim(BOTH 'x' FROM 'xax')",
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

/// Syntax sqlparser takes from other dialects: the second parser refuses
/// it at the guard, and the target would have rejected it too — the guard
/// no longer forwards text whose reading it cannot confirm.
const SQLPARSER_ONLY: &[&str] = &[
    "SELECT relname FROM pg_class QUALIFY relname = 'x'",
    "SELECT TOP 1 relname FROM pg_class",
    "SELECT relname FROM pg_class GROUP BY ALL",
    "SELECT [1, 2]",
    "SELECT relname FROM pg_class CONNECT BY PRIOR oid = relnamespace",
];

#[tokio::test]
#[serial_test::parallel(world)]
async fn syntax_only_the_guard_parser_reads_is_refused() {
    let mut conn = connect().await;
    for sql in SQLPARSER_ONLY {
        assert_eq!(
            is_read_only(sql),
            Err(GuardError::ParserDisagreement("syntax")),
            "{sql:?}"
        );
        assert_eq!(as_postgres_reads(&mut conn, sql).await, None, "{sql:?}");
    }
}

/// A set-returning call in FROM is a table factor, not an expression: the
/// comparison must see it, or a denied one there would never be compared.
#[tokio::test]
#[serial_test::parallel(world)]
async fn from_clause_calls_enter_the_comparison() {
    let mut conn = connect().await;
    let reading = as_postgres_reads(&mut conn, "SELECT * FROM generate_series(1, 3)")
        .await
        .expect("the target accepts it");
    assert!(
        calls(&reading).contains("generate_series"),
        "FROM-clause call missed:\n{reading}"
    );
}

/// `alias.name` calls `name` with the alias's whole row — but only a
/// function that takes a row: the guard admits these qualified columns
/// because Postgres finds no call in them (`row_to_json` is the control).
#[tokio::test]
#[serial_test::parallel(world)]
async fn whole_row_notation_reaches_only_row_arguments() {
    let mut conn = connect().await;
    for sql in [
        "SELECT t.setseed FROM (SELECT 0.5::float8) t",
        "SELECT t.pg_notify FROM (SELECT 'c'::text, 'p'::text) t",
        "SELECT t.pg_read_file FROM (SELECT 'f'::text) t",
        "SELECT t.set_config FROM (SELECT 'a'::text, 'b'::text, false) t",
    ] {
        assert_eq!(is_read_only(sql), Ok(()), "must stay admitted: {sql:?}");
        let reading = as_postgres_reads(&mut conn, sql).await;
        assert_eq!(reading, None, "Postgres resolved a call in {sql:?}");
    }
    let control = "SELECT t.row_to_json FROM (SELECT 1 AS a) t";
    let reading = as_postgres_reads(&mut conn, control)
        .await
        .expect("the target accepts the control");
    assert!(calls(&reading).contains("row_to_json"), "{reading}");
}

/// The columns the guard's parser gives a `SELECT`: a name, or `None` where
/// only Postgres knows it. `None` altogether for a wildcard or another shape.
fn columns_the_guard_reads(sql: &str) -> Option<Vec<Option<String>>> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql).ok()?;
    let Some(Statement::Query(query)) = statements.first() else {
        return None;
    };
    let mut body = query.body.as_ref();
    while let SetExpr::SetOperation { left, .. } = body {
        body = left.as_ref();
    }
    let SetExpr::Select(select) = body else {
        return None;
    };
    let folded = |ident: &sqlparser::ast::Ident| match ident.quote_style {
        None => ident.value.to_ascii_lowercase(),
        Some(_) => ident.value.clone(),
    };
    let column = |item: &SelectItem| match item {
        SelectItem::ExprWithAlias { alias, .. } => Some(Some(folded(alias))),
        SelectItem::UnnamedExpr(Expr::Identifier(ident)) => Some(Some(folded(ident))),
        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => Some(parts.last().map(folded)),
        SelectItem::UnnamedExpr(_) => Some(None),
        _ => None,
    };
    select.projection.iter().map(column).collect()
}

/// The columns the target describes, without executing; `None` when it
/// rejects the text. Any other failure is the test's.
async fn columns_postgres_describes(conn: &mut PgConnection, sql: &str) -> Option<Vec<String>> {
    let text = sqlx::AssertSqlSafe(sql.to_owned()).into_sql_str();
    let statement = match conn.prepare(text).await {
        Ok(statement) => statement,
        Err(sqlx::Error::Database(err))
            if err
                .code()
                .is_some_and(|c| ["42", "22", "0A"].contains(&&c[..2])) =>
        {
            return None;
        }
        Err(err) => panic!("describing {sql:?}: {err}"),
    };
    let names = statement.columns().iter().map(|c| c.name().to_owned());
    Some(names.collect())
}

/// Reads to compare column by column.
const PROJECTIONS: &[&str] = &[
    "SELECT 1",
    "SELECT 1 AS a, 2 b, 3 AS \"C\"",
    "SELECT relname, oid AS id FROM pg_class",
    "SELECT c.relname AS end, c.oid FROM pg_class c",
    "SELECT count(*) FROM pg_class GROUP BY relkind",
    "SELECT CASE WHEN true THEN 1 END",
    "SELECT CASE WHEN true THEN 1 END AS x, 2",
    "SELECT 1 UNION SELECT 2",
    "WITH w AS (SELECT 1 AS a) SELECT a FROM w",
    "SELECT relname FROM pg_class ORDER BY oid LIMIT 1",
    "SELECT interval '1 day' AS i",
    "SELECT 'a' LIKE 'b', NOT true",
];

/// What may follow a statement's text, or not.
const FOLLOWED_BY: &[&str] = &[
    "",
    ";",
    " -- END, 2",
    " END",
    " end, 2",
    " END, 2 AS b",
    " END FROM pg_class",
    "\nEND\n, 2",
    " END END, 3",
    " AS end",
    " AS end, 2",
    " AS x, 2 END, 3",
    " x",
    " x, 2",
    ", 2",
    ", 2 y",
    " AND, 2",
    " AND true, 2",
    " FROM pg_class",
    " BEGIN, 2",
    " COMMIT, 2",
    " GO, 2",
];

/// Every column Postgres describes, in order and by name, is one the guard
/// read: no admitted statement holds text only the target reads.
#[tokio::test]
#[serial_test::parallel(world)]
async fn the_guard_reads_every_column_postgres_describes() {
    let mut conn = connect().await;
    let mut compared = 0;
    for projection in PROJECTIONS {
        for tail in FOLLOWED_BY {
            let sql = format!("{projection}{tail}");
            if is_read_only(&sql).is_err() {
                continue;
            }
            let Some(described) = columns_postgres_describes(&mut conn, &sql).await else {
                continue;
            };
            let read = columns_the_guard_reads(&sql).expect("a projection");
            assert_eq!(
                read.len(),
                described.len(),
                "{sql:?}: {read:?} {described:?}"
            );
            for (read, described) in read.iter().zip(&described) {
                if let Some(read) = read {
                    assert_eq!(read, described, "{sql:?}");
                }
            }
            compared += 1;
        }
    }
    assert!(compared >= 80, "only {compared} statements were compared");
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
