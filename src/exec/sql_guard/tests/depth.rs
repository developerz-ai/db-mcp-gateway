//! How deep a statement may nest: the same on every caller's stack, and a
//! typed refusal past it, never an exhausted stack.

use super::*;
use crate::exec::sql_guard::bounds::{MAX_JOINS, MAX_SELECTS, MAX_SQL_BYTES};

/// The worker thread's stack Tokio sizes, and one too small for either parser.
const CALLER_STACKS: [usize; 2] = [2 << 20, 256 << 10];

fn on_stack<T: Send + 'static>(bytes: usize, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(bytes)
        .spawn(f)
        .expect("thread spawns")
        .join()
        .expect("the guard returns")
}

/// One way a statement nests or chains, `n` links of it.
type Family = (&'static str, fn(usize) -> String);

const FAMILIES: &[Family] = &[
    ("+", |n| format!("SELECT a{}", "+a".repeat(n))),
    ("||", |n| format!("SELECT a{}", " || a".repeat(n))),
    ("::", |n| format!("SELECT a{}", "::text".repeat(n))),
    ("->", |n| format!("SELECT a{}", "->'a'".repeat(n))),
    ("AND", |n| format!("SELECT 1 WHERE a{}", " AND a".repeat(n))),
    ("OR", |n| format!("SELECT 1 WHERE a{}", " OR a".repeat(n))),
    ("AND OR", |n| {
        format!("SELECT 1 WHERE a{}", " AND a OR a".repeat(n))
    }),
    ("IS NULL", |n| format!("SELECT a{}", " IS NULL".repeat(n))),
    ("COLLATE", |n| format!("SELECT a{}", " COLLATE c".repeat(n))),
    ("AT TIME ZONE", |n| {
        format!("SELECT a{}", " AT TIME ZONE z".repeat(n))
    }),
    ("JOIN", |n| {
        format!("SELECT 1 FROM t{}", " JOIN u ON true".repeat(n))
    }),
    ("comma", |n| format!("SELECT 1 FROM t{}", ",u".repeat(n))),
    ("UNION ALL", |n| {
        format!("SELECT 1{}", " UNION ALL SELECT 2".repeat(n))
    }),
    ("CTEs", |n| {
        let ctes: Vec<_> = (0..n).map(|i| format!("c{i} AS (SELECT 1)")).collect();
        format!("WITH {} SELECT 1", ctes.join(","))
    }),
    ("IN list", |n| {
        format!("SELECT 1 WHERE a IN (1{})", ",1".repeat(n))
    }),
    ("WHENs", |n| {
        format!("SELECT CASE{} END", " WHEN a THEN 1".repeat(n))
    }),
    ("subscripts", |n| format!("SELECT a{}", "[1]".repeat(n))),
    ("fields", |n| format!("SELECT (a){}", ".f".repeat(n))),
    ("array dimensions", |n| {
        format!("SELECT a::int{}", "[]".repeat(n))
    }),
    ("-", |n| format!("SELECT {}a", "- ".repeat(n))),
    ("NOT", |n| format!("SELECT {}a", "NOT ".repeat(n))),
    ("CASE", |n| {
        format!(
            "SELECT {}0{}",
            "CASE WHEN a THEN 1 ELSE ".repeat(n),
            " END".repeat(n)
        )
    }),
    ("parens", |n| {
        format!("SELECT {}a{}", "(".repeat(n), ")".repeat(n))
    }),
    ("calls", |n| {
        format!("SELECT {}a{}", "f(".repeat(n), ")".repeat(n))
    }),
    ("ARRAY", |n| {
        format!("SELECT {}1{}", "ARRAY[".repeat(n), "]".repeat(n))
    }),
    ("OVER", |n| {
        format!(
            "SELECT {}a{}",
            "f() OVER (ORDER BY ".repeat(n),
            ")".repeat(n)
        )
    }),
    ("FROM (SELECT", |n| {
        format!(
            "SELECT * FROM {}t{}",
            "(SELECT * FROM ".repeat(n),
            ") s".repeat(n)
        )
    }),
    ("(SELECT", |n| {
        format!("SELECT {}1{}", "(SELECT ".repeat(n), ")".repeat(n))
    }),
    ("AND (OR (", |n| {
        format!(
            "SELECT 1 WHERE {}a{}",
            "a AND (a OR (".repeat(n),
            "))".repeat(n)
        )
    }),
    ("JOIN in parens", |n| {
        format!(
            "SELECT 1 FROM {}t{}",
            "(".repeat(n),
            " JOIN u ON true)".repeat(n)
        )
    }),
    ("UNION in parens", |n| {
        format!(
            "{}SELECT 1{}",
            "(".repeat(n),
            " UNION ALL SELECT 2)".repeat(n)
        )
    }),
    ("WITH in WITH", |n| {
        format!(
            "{}SELECT 1{}",
            "WITH c AS (".repeat(n),
            ") SELECT 1".repeat(n)
        )
    }),
    ("JSON_TABLE", |n| {
        let (open, close) = ("NESTED PATH '$' COLUMNS (".repeat(n), ")".repeat(n));
        format!("SELECT * FROM JSON_TABLE(j, '$' COLUMNS ({open}a int PATH '$'{close}))")
    }),
];

fn family(name: &str) -> fn(usize) -> String {
    let found = FAMILIES.iter().find(|(n, _)| *n == name);
    found.expect("a family of that name").1
}

/// The most links that fit in the length bound.
fn longest(links: fn(usize) -> String) -> usize {
    let (mut fits, mut over) = (0, MAX_SQL_BYTES);
    while over - fits > 1 {
        let n = usize::midpoint(fits, over);
        if links(n).len() <= MAX_SQL_BYTES {
            fits = n;
        } else {
            over = n;
        }
    }
    fits
}

/// At the length bound, and at every size another limit stops at.
#[test]
fn every_family_gets_an_answer_at_every_size_on_any_stack() {
    for (name, links) in FAMILIES {
        let max = longest(*links);
        let sizes = [31, 62, 63, 124, 125, 127, 128, 512, 1023, 1024, 4995, 4996];
        for n in sizes.into_iter().filter(|n| *n < max).chain([max]) {
            for stack in CALLER_STACKS {
                let sql = links(n);
                let got = on_stack(stack, move || is_read_only(&sql));
                let answered = matches!(
                    got,
                    Ok(())
                        | Err(GuardError::TooDeep
                            | GuardError::TooComplex { .. }
                            | GuardError::Parse(_)
                            | GuardError::ParserDisagreement("syntax"))
                );
                assert!(answered, "{name} x {n} on {stack}: {got:?}");
            }
        }
    }
}

/// Sizes generated queries reach.
#[test]
fn long_generated_queries_are_admitted() {
    for (name, n) in [
        ("+", 1000),
        ("||", 1000),
        ("::", 1000),
        ("->", 1000),
        ("AND", 5000),
        ("OR", 5000),
        ("JOIN", MAX_JOINS),
        ("UNION ALL", MAX_SELECTS - 1),
        ("CTEs", 500),
        ("IN list", 10_000),
        ("WHENs", 2000),
        ("CASE", 100),
        ("NOT", 100),
        ("parens", 100),
        ("calls", 100),
        ("(SELECT", 50),
        ("FROM (SELECT", 50),
    ] {
        let sql = family(name)(n);
        assert_eq!(is_read_only(&sql), Ok(()), "{name} x {n}");
    }
}

/// Where the second parser's own limit falls, whatever the caller's stack.
#[test]
fn chains_past_the_serialisers_limit_are_refused_on_any_stack() {
    for stack in CALLER_STACKS {
        for (n, want) in [(4995, Ok(())), (4996, Err(GuardError::TooDeep))] {
            for name in ["+", "||", "::"] {
                let sql = family(name)(n);
                let got = on_stack(stack, move || is_read_only(&sql));
                assert_eq!(got, want, "{name} x {n} on {stack}");
            }
        }
    }
    let message = GuardError::TooDeep.to_string();
    assert!(message.contains("concat("), "{message}");
    ok(&format!("SELECT concat({})", vec!["'x'"; 8000].join(", ")));
}

/// The deepest trees, more at once than there are parser threads.
#[test]
fn deep_statements_at_once_get_answers() {
    std::thread::scope(|scope| {
        for i in 0..24 {
            scope.spawn(move || {
                let n = if i % 2 == 0 { 4990 } else { 30_000 };
                let got = is_read_only(&family("+")(n));
                assert_eq!(got.is_ok(), n < 4996, "{n}: {got:?}");
            });
        }
    });
}
