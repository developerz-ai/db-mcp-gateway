//! The budget changes what is read not at all: the same tree comes of the same
//! text.

use sqlparser::dialect::{Dialect, PostgreSqlDialect};
use sqlparser::keywords::ALL_KEYWORDS;

use super::*;

/// `metered` must list every method Postgres's dialect overrides.
#[test]
fn metered_dialect_reads_as_postgres_dialect() {
    let mut statements: Vec<String> = [
        "SELECT a::int, b->>'c', d @> e, f ^ 2, g COLLATE \"C\", h AT TIME ZONE 'x' FROM t",
        "SELECT sum(a) FILTER (WHERE b), c FROM t GROUP BY GROUPING SETS ((c), ())",
        "SELECT f(a => 1, b := 2), xmlelement(name a), interval '1' day, 5 !",
        "SELECT * FROM ONLY t TABLESAMPLE system (1), t2 *, LATERAL f(x) WITH ORDINALITY",
        "SELECT FROM t ORDER BY a USING < , b NULLS LAST",
        "SELECT a.* AS x, (b).c, d[1:2], e[1] FROM t",
        "SELECT 'a' BETWEEN b = c AND d, e NOTNULL, f ~~ g, #h, i << 1, 1_000, 0xFF",
        "SELECT trim('a', 'b'), extract(century FROM a), extract('x' FROM b), public.t 'x'",
        "WITH a AS NOT MATERIALIZED (SELECT 1) SELECT * FROM a JOIN b JOIN c ON d ON e",
        "INSERT INTO t AS x VALUES (1) ON CONFLICT DO NOTHING RETURNING *",
        "EXPLAIN (FORMAT JSON, COSTS) SELECT 1",
        "COMMENT ON TABLE t IS 'x'",
        "CREATE INDEX i ON t (a) WITH (fillfactor = 1)",
        "ALTER TABLE t ADD COLUMN IF NOT EXISTS a int[], ADD EXCLUDE USING gist (a WITH =)",
        "CREATE TABLE t (LIKE u INCLUDING ALL)",
        "LOAD 'x'",
        "LISTEN a",
        "NOTIFY a, 'b'",
        "SET NAMES 'x'",
        "DROP GROUP g",
        "CREATE GROUP g",
        "ALTER USER u SET a = 1",
    ]
    .map(str::to_owned)
    .into();
    for word in ALL_KEYWORDS {
        for (before, after) in [
            ("SELECT ", ""),
            ("SELECT a ", ""),
            ("SELECT a AS ", ""),
            ("SELECT ", "('a')"),
            ("SELECT ", " 'a'"),
            ("SELECT ", " a"),
            ("SELECT 1 FROM ", ""),
            ("SELECT 1 FROM t ", ""),
            ("SELECT 1 FROM t AS ", " JOIN u ON a"),
            ("SELECT a ", " b"),
            ("SELECT 1 FROM t ", " b"),
            ("", " a"),
        ] {
            statements.push(format!("{before}{word}{after}"));
        }
    }
    let read = |dialect: &dyn Dialect, sql: &str| {
        Parser::new(dialect)
            .try_with_sql(sql)
            .and_then(|mut parser| parser.parse_statements())
    };
    for sql in &statements {
        let (metered, _) = metered(usize::MAX, |dialect| Ok(read(dialect, sql)));
        assert_eq!(metered, Ok(read(&PostgreSqlDialect {}, sql)), "{sql}");
    }
}

/// Runs of whitespace and comments are passed over once.
#[test]
fn whitespace_does_not_change_the_tree() {
    let tree = |sql: &str| parse::parse(sql).expect("parses");
    for (spaced, plain) in [
        ("SELECT  a ,\n\n\tb", "SELECT a , b"),
        ("SELECT/**/ /**/a--x\n--y\n+ 1", "SELECT a\n+ 1"),
        (" /* a */ SELECT 'a /**/  b' ; -- c", "SELECT 'a /**/  b' ;"),
        ("SELECT a . b,  c . *  FROM t", "SELECT a . b, c . * FROM t"),
    ] {
        let normal = |sql| {
            format!(
                "{:?}",
                tree(sql)
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            )
        };
        assert_eq!(normal(spaced), normal(plain), "{spaced:?}");
    }
}
