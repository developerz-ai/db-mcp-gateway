use proptest::prelude::*;

use super::*;
use crate::exec::sql_guard::bounds::{MAX_JOINS, MAX_PARENS, MAX_SELECTS, MAX_SQL_BYTES};

/// A worker thread's stack, as Tokio sizes it.
const WORKER_STACK: usize = 2 << 20;

/// `(opening, repeated part)`: every way a statement grows by repetition.
const REPEATED: &[(&str, &str)] = &[
    ("SELECT a", "+a"),
    ("SELECT a", "||a"),
    ("SELECT a", "=a"),
    ("SELECT a", "^a"),
    ("SELECT a", "~a"),
    ("SELECT a", "->a"),
    ("SELECT a", "#>>a"),
    ("SELECT a", "@>a"),
    ("SELECT 1", " !"),
    ("SELECT a", "::a"),
    ("SELECT a::int", "[]"),
    ("SELECT a", "[1]"),
    ("SELECT a", ".b"),
    ("SELECT a", " COLLATE c"),
    ("SELECT a", " AT TIME ZONE b"),
    ("SELECT a", " IS NULL"),
    ("SELECT a", " ISNULL"),
    ("SELECT a", " NOTNULL"),
    ("SELECT a", " IS TRUE"),
    ("SELECT a", " IS DISTINCT FROM a"),
    ("SELECT a", " AND a"),
    ("SELECT a", " OR a"),
    ("SELECT a", " LIKE a"),
    ("SELECT a", " ILIKE a"),
    ("SELECT a", " SIMILAR TO a"),
    ("SELECT a", " BETWEEN a AND a"),
    ("SELECT a", " IN(1)"),
    ("SELECT a", " NOT IN(1)"),
    ("SELECT a", "=ANY(b)"),
    ("SELECT a", " OPERATOR(+)a"),
    ("SELECT a", ",a"),
    ("SELECT ", "NOT "),
    ("SELECT ", "- "),
    ("SELECT ", "("),
    ("SELECT ", "f("),
    ("SELECT ", "ARRAY["),
    ("SELECT ", "CASE WHEN a THEN "),
    ("SELECT ", "EXISTS(SELECT "),
    ("SELECT CASE", " WHEN a THEN 1"),
    ("SELECT 1", " UNION SELECT 1"),
    ("SELECT 1", " EXCEPT SELECT 1"),
    ("SELECT 1", " INTERSECT SELECT 1"),
    ("VALUES(1)", "UNION VALUES(1)"),
    ("SELECT 1 FROM t", " JOIN t ON a"),
    ("SELECT 1 FROM t", " JOIN t"),
    ("SELECT 1 FROM t", " LEFT JOIN t"),
    ("SELECT 1 FROM t", " CROSS JOIN t"),
    ("SELECT 1 FROM t", " JOIN(t"),
    ("SELECT 1 FROM t", " PIVOT(f() FOR a IN(ANY))"),
    (
        "SELECT 1 FROM JSON_TABLE('a','$' COLUMNS(",
        "NESTED '' COLUMNS(",
    ),
    ("CREATE USER a ", "k=("),
    ("", "SELECT * FROM ("),
    ("", "WITH a AS ("),
    ("", "EXPLAIN "),
    ("", "IF a THEN "),
    ("", "("),
    ("SELECT 1", ";SELECT 1"),
    ("SELECT 1", " /*"),
];

fn to_length(opening: &str, part: &str, bytes: usize) -> String {
    let parts = (bytes - opening.len()) / part.len();
    format!("{opening}{}", part.repeat(parts))
}

fn on_worker_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK)
        .spawn(f)
        .expect("thread spawns")
        .join()
        .expect("the guard returns")
}

#[test]
fn every_repetition_at_the_length_cap_gets_an_answer_on_a_worker_stack() {
    for (opening, part) in REPEATED {
        let sql = to_length(opening, part, MAX_SQL_BYTES);
        on_worker_stack(move || {
            for access in [Access::ReadOnly, Access::ReadWrite] {
                let _ = check_sql(&sql, access);
            }
            let _ = statement_body(&sql);
        });
    }
}

/// The parser's limits reached together: nested joins up to the bound, then
/// nested expressions, then a chain over the rest of the length — complete,
/// and ending in text that does not parse, so the tree is dropped under them.
#[test]
fn structures_at_their_bounds_together_get_an_answer() {
    let calls = [
        "",
        "f(",
        "CASE WHEN ",
        "EXISTS(SELECT ",
        "(SELECT * FROM t JOIN f(",
    ];
    for (call, link) in calls
        .into_iter()
        .flat_map(|c| ["+a", "||a", "::a", "=a"].map(|l| (c, l)))
    {
        for depth in [1, 10, 20, 40] {
            for ending in ["", ") ON a", " nonsense nonsense", " ("] {
                let opening = format!("{} JOIN f({}a", joins(MAX_JOINS - 64), call.repeat(depth));
                let room = MAX_SQL_BYTES - opening.len() - ending.len();
                let sql = format!("{opening}{}{ending}", link.repeat(room / link.len()));
                on_worker_stack(move || {
                    let _ = is_read_only(&sql);
                });
            }
        }
    }
}

/// A join without a constraint, from a few to the length cap, on a worker
/// stack: answered up to the bound and refused past it.
#[test]
fn joins_without_constraint_at_every_size() {
    for n in [100, 300, MAX_JOINS, MAX_JOINS + 1, 1000, 2440, 9000] {
        let got = on_worker_stack(move || is_read_only(&joins(n)));
        assert_eq!(got.is_ok(), n <= MAX_JOINS, "{n} joins: {got:?}");
    }
}

/// The tree is dropped on every way out: admitted, refused by shape or by
/// name after parsing, one of several statements, or unparseable at the end.
#[test]
fn every_outcome_at_the_length_cap_gets_an_answer_on_a_worker_stack() {
    type Expected = fn(&Result<(), GuardError>) -> bool;
    let outcomes: [(&str, &str, Expected); 6] = [
        ("SELECT a", "", |r| r.is_ok()),
        ("SELECT lo_creat(1), a", "", |r| {
            matches!(r, Err(GuardError::DeniedFunction(_)))
        }),
        ("DELETE FROM t WHERE a", "", |r| {
            matches!(r, Err(GuardError::NotAllowed(_)))
        }),
        ("SELECT a", ";SELECT 1", |r| {
            matches!(r, Err(GuardError::MultiStatement(2)))
        }),
        ("SELECT a", " )", |r| matches!(r, Err(GuardError::Parse(_)))),
        ("EXPLAIN ANALYZE SELECT a", "", |r| {
            matches!(r, Err(GuardError::ExplainAnalyze))
        }),
    ];
    for (opening, ending, expected) in outcomes {
        for part in ["+a", "||a", "::a", "=a", " AND a"] {
            let body = to_length(opening, part, MAX_SQL_BYTES - ending.len());
            let sql = format!("{body}{ending}");
            let got = on_worker_stack(move || is_read_only(&sql));
            assert!(expected(&got), "{opening} … {part} … {ending}: {got:?}");
        }
    }
}

/// `NOT` and `CASE` nested past the parser's own limit are parse errors.
#[test]
fn nesting_past_the_parser_limit_is_a_parse_error_on_a_worker_stack() {
    for part in ["NOT ", "CASE WHEN a THEN ", "- "] {
        for n in [60, 1000, 3000] {
            let sql = format!("SELECT {}a", part.repeat(n));
            let got = on_worker_stack(move || is_read_only(&sql));
            assert!(
                matches!(got, Err(GuardError::Parse(_))),
                "{part} {n}: {got:?}"
            );
        }
    }
}

/// Generous for a loaded machine: the slowest takes about 60 ms optimised.
/// What it guards against is time that grows faster than the text.
#[test]
fn openers_repeated_or_alternating_answer_in_bounded_time() {
    const OPENERS: &[&str] = &[
        "(",
        "f(",
        "ARRAY[",
        "CASE ",
        "CASE WHEN ",
        "NOT ",
        "EXISTS(SELECT ",
        "(SELECT ",
        "CAST(",
        "CAST(CASE ",
        "IF(",
        "current_time(",
        "INTERVAL ",
        "ROW(",
        "VALUES(",
        "a IN (",
        "a[",
        "a.",
        "f(a=>",
        "TRIM(",
        "LATERAL (",
        "SELECT * FROM (",
    ];
    let pairs = OPENERS
        .iter()
        .flat_map(|a| OPENERS.iter().map(move |b| format!("{a}{b}")));
    for unit in pairs {
        for n in [12, 24, 48] {
            let sql = format!("SELECT {}1", unit.repeat(n));
            let started = std::time::Instant::now();
            let _ = on_worker_stack(move || is_read_only(&sql));
            let took = started.elapsed();
            assert!(took.as_secs() < 5, "{unit:?} x {n}: {took:?}");
        }
    }
}

#[test]
fn concurrent_statements_at_the_bounds_get_answers() {
    let threads: Vec<_> = (0..16)
        .map(|i| {
            std::thread::Builder::new()
                .stack_size(WORKER_STACK)
                .spawn(move || match i % 2 {
                    0 => is_read_only(&to_length("SELECT a", "+a", MAX_SQL_BYTES)).map(|()| i),
                    _ => is_read_only(&joins(MAX_JOINS)).map(|()| i),
                })
                .expect("thread spawns")
        })
        .collect();
    for thread in threads {
        assert!(thread.join().expect("the guard returns").is_ok());
    }
}

fn joins(n: usize) -> String {
    format!("SELECT 1 FROM t{}", " JOIN t".repeat(n))
}

fn selects(n: usize) -> String {
    vec!["SELECT 1"; n].join(" UNION ALL ")
}

/// Nested options, the one place sqlparser takes more than 50 levels.
fn parens(n: usize) -> String {
    format!("CREATE USER a k={}1{}", "(k=".repeat(n), ")".repeat(n))
}

fn too_complex(sql: &str, limit: usize, what: &'static str) {
    rejected(sql, GuardError::TooComplex { limit, what });
}

#[test]
fn bounds_are_exact() {
    ok(&joins(MAX_JOINS));
    too_complex(&joins(MAX_JOINS + 1), MAX_JOINS, "joins");
    ok(&selects(MAX_SELECTS));
    too_complex(&selects(MAX_SELECTS + 1), MAX_SELECTS, "SELECTs");
    rejected_not_allowed(&parens(MAX_PARENS), "unsupported");
    too_complex(&parens(MAX_PARENS + 1), MAX_PARENS, "levels of parentheses");
    let padded = |bytes: usize| format!("SELECT '{}'", "x".repeat(bytes - 9));
    ok(&padded(MAX_SQL_BYTES));
    too_complex(&padded(MAX_SQL_BYTES + 1), MAX_SQL_BYTES, "bytes");
}

#[test]
fn length_bound_is_the_tool_edges() {
    assert_eq!(MAX_SQL_BYTES, crate::audit::AUDIT_SQL_MAX_BYTES);
}

#[test]
fn bounds_count_keywords_and_open_parentheses_only() {
    let quoted = vec!["'join'"; MAX_JOINS + 1].join(", ");
    ok(&format!("SELECT {quoted} -- {}", "JOIN ".repeat(600)));
    ok(&format!("SELECT {}", vec!["\"join\""; 600].join(", ")));
    ok(&format!(
        "SELECT {}",
        vec!["f(1)"; MAX_PARENS * 4].join(", ")
    ));
    too_complex(
        &joins(MAX_JOINS + 1).replace(" JOIN", " jOiN"),
        MAX_JOINS,
        "joins",
    );
}

#[test]
fn message_names_the_limit_and_the_remedy() {
    let message = is_read_only(&joins(MAX_JOINS + 1))
        .expect_err("refused")
        .to_string();
    assert_eq!(
        message,
        "the statement has more than 512 joins; split it into smaller statements"
    );
}

/// Sizes real reports and filters reach.
#[test]
fn large_ordinary_statements_stay_admitted() {
    let repeat = |part: &str, n: usize| part.repeat(n);
    ok(&format!(
        "SELECT 1 FROM t WHERE a = 1{}",
        repeat(" OR t.a = 'x'", 1000)
    ));
    ok(&format!(
        "SELECT 1 FROM t WHERE a = 1{}",
        repeat(" AND (t.b <> 2)", 1000)
    ));
    ok(&format!(
        "SELECT 1 FROM t WHERE id IN (1{})",
        repeat(", 1234567", 5000)
    ));
    ok(&format!(
        "SELECT 1 FROM t{}",
        (0..100)
            .map(|i| format!(" LEFT JOIN u{i} ON u{i}.t_id = t.id"))
            .collect::<String>()
    ));
    ok(&format!(
        "SELECT a, b FROM t{}",
        repeat(" UNION ALL SELECT a, b FROM t JOIN u USING (id)", 200)
    ));
    ok(&format!(
        "SELECT CASE{} END FROM t",
        repeat(" WHEN a = 1 THEN 'x'", 100)
    ));
    ok(&format!("SELECT {}", vec!["a"; 2000].join(" || ")));
    let insert = format!(
        "INSERT INTO t VALUES (1, 'a'){}",
        repeat(", (1, 'a')", 5000)
    );
    assert_eq!(check_sql(&insert, Access::ReadWrite), Ok(()));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any mix of the repeated parts, up to the cap, gets an answer.
    #[test]
    fn any_mix_of_repetitions_gets_an_answer_on_a_worker_stack(
        runs in proptest::collection::vec((0..REPEATED.len(), 1usize..6000), 1..6)
    ) {
        let mut sql = String::from(REPEATED[runs[0].0].0);
        for (family, n) in runs {
            sql.push_str(&REPEATED[family].1.repeat(n));
        }
        sql.truncate(MAX_SQL_BYTES);
        on_worker_stack(move || {
            let _ = is_read_only(&sql);
        });
    }

    /// No arrangement hides a join from the count.
    #[test]
    fn joins_over_the_bound_are_refused_however_arranged(
        extra in 1usize..40,
        constraint in proptest::sample::select(vec!["", " ON a", " USING (a)", " AS on", ", u", " UNION SELECT 1 FROM t"]),
    ) {
        let sql = format!("SELECT 1 FROM t{}", format!(" JOIN t{constraint}").repeat(MAX_JOINS + extra));
        let refused = matches!(is_read_only(&sql), Err(GuardError::TooComplex { .. }));
        prop_assert!(refused, "admitted: {constraint:?}");
    }
}
