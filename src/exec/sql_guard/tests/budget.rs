//! The parser's work budget: nesting that multiplies the parser's attempts is
//! refused in bounded time, and nothing else is.

use std::sync::mpsc::channel;
use std::time::Duration;

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

use super::*;
use crate::exec::sql_guard::bounds::MAX_SQL_BYTES;
use crate::exec::sql_guard::budget::{Work, allowance, metered};
use crate::exec::sql_guard::parse::measured;

mod properties;
mod same_reading;

/// For one short statement in a debug build on a loaded machine.
const SOON: Duration = Duration::from_secs(2);

/// For one statement at the length cap, the same.
const AT_THE_CAP: Duration = Duration::from_secs(20);

/// `f`'s answer within `deadline`: a thread without one is left behind.
fn soon<T: Send + 'static>(
    deadline: Duration,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (answer, answered) = channel();
    std::thread::spawn(move || answer.send(f()));
    answered
        .recv_timeout(deadline)
        .unwrap_or_else(|err| panic!("{what}: {err}"))
}

fn guarded(deadline: Duration, sql: String) -> Result<(), GuardError> {
    let what = sql.chars().take(60).collect::<String>();
    soon(deadline, &what, move || is_read_only(&sql))
}

fn nested(opening: &str, inner: &str, closing: &str, levels: usize) -> String {
    format!(
        "SELECT {}{inner}{}",
        opening.repeat(levels),
        closing.repeat(levels)
    )
}

fn work(sql: &str) -> Work {
    measured(sql).expect("tokens").1
}

#[test]
fn retried_nesting_is_refused_soon_naming_the_budget() {
    for (opening, closing) in [("NOT (a).", ""), ("CAST(a.", " AS int)")] {
        for levels in [24, 32, 40] {
            let sql = nested(opening, "x", closing, levels);
            let got = guarded(SOON, sql.clone());
            let limit = match got {
                Err(GuardError::TooMuchWork { limit }) => limit,
                other => panic!("{opening} x {levels}: {other:?}"),
            };
            assert_eq!(
                got.expect_err("refused").to_string(),
                format!(
                    "the statement exceeds the parser work budget ({limit} steps at its \
                     length); nest it less deeply or split it into smaller statements"
                )
            );
            assert_eq!(limit, work(&sql).allowance);
        }
        // Past the parser's own depth limit it may say so first.
        let got = guarded(SOON, nested(opening, "x", closing, 64));
        assert!(
            matches!(
                got,
                Err(GuardError::TooMuchWork { .. } | GuardError::Parse(_))
            ),
            "{opening} x 64: {got:?}"
        );
    }
}

/// The budget grows with the text, and a token's length is part of its cost.
#[test]
fn retried_nesting_in_a_statement_at_the_length_cap_is_refused() {
    let long = "z".repeat(24_000);
    for opening in ["NOT (a).", "CAST(a.", "(a).NOT "] {
        let core = opening.repeat(40);
        for leaf in ["x".to_owned(), format!("\"{long}\""), format!("'{long}'")] {
            let room = MAX_SQL_BYTES - core.len() - leaf.len() - 16;
            for pad in [",a", ",f()", "+a", "/**/"] {
                let pad = pad.repeat(room / pad.len());
                let got = guarded(AT_THE_CAP, format!("SELECT {core}{leaf}{pad}"));
                assert!(got.is_err(), "{opening} {pad:.8}: {got:?}");
            }
        }
    }
}

#[test]
fn a_parse_past_its_allowance_keeps_nothing() {
    for steps in 0..20 {
        let (parsed, work) = metered(steps, |dialect| {
            let parser = Parser::new(dialect).try_with_sql("SELECT a + 1 FROM t");
            Ok(parser.and_then(|mut parser| parser.parse_statements()))
        });
        assert_eq!(parsed, Err(GuardError::TooMuchWork { limit: steps }));
        assert_eq!(work.allowance, steps);
        assert!(work.steps > steps);
    }
}

#[test]
#[should_panic(expected = "not the budget")]
fn another_panic_stays_a_panic() {
    let _ = metered(10, |_| -> Result<(), GuardError> {
        panic!("not the budget")
    });
}

/// The parser copies a token each time it looks at it.
#[test]
fn a_long_token_costs_by_its_length() {
    let tag = format!("$t{}$", "z".repeat(32_000));
    let dollar = format!("{tag}x{tag}");
    for quoted in ["'", "\""] {
        let long = format!("SELECT {quoted}{}{quoted}", "z".repeat(32_000));
        let (short, long) = (work("SELECT 'z'").steps, work(&long).steps);
        assert!(long > short + 32_000 / 16, "{quoted}: {short} {long}");
    }
    let (short, long) = (
        work("SELECT $t$x$t$").steps,
        work(&format!("SELECT {dollar}")).steps,
    );
    assert!(
        long > short + 32_000 / 16,
        "a long dollar tag: {short} {long}"
    );
}

#[test]
fn allowance_grows_with_the_text() {
    assert_eq!(allowance(0, 0), 25_000);
    assert_eq!(allowance(10, 100), 25_340);
    assert_eq!(allowance(usize::MAX, usize::MAX), usize::MAX);
}

/// Repeated to the length cap: the most work per token statements do, and none
/// takes half of its allowance.
#[test]
fn ordinary_statements_at_the_cap_stay_well_within() {
    for (opening, part, closing) in [
        ("SELECT 1", ",a", ""),
        ("SELECT 1", ",f()", ""),
        ("SELECT 1", ",position(a,b)", ""),
        ("SELECT 1", ",NOT NOT NOT NOT a", ""),
        ("SELECT 1", ",CASE WHEN NOT (a) THEN (b) END", ""),
        ("SELECT 1", ",coalesce(a::numeric(1,2), 0)", ""),
        (
            "SELECT 1",
            ",sum(a) FILTER (WHERE b) OVER (PARTITION BY c)",
            "",
        ),
        ("SELECT 1", ",extract(epoch from now() - a)", ""),
        ("SELECT 1", ",interval '1 day' * (a)", ""),
        ("SELECT 1", ",(SELECT max(a) FROM t)", ""),
        ("SELECT a IN (1", ",'x'", ")"),
        ("SELECT a", "+a", ""),
        ("SELECT a", "||a", ""),
        ("SELECT a", "::int", ""),
        ("SELECT a", " AND ((b = 1 OR c = 2))", ""),
        ("SELECT 1 FROM t", ", f(a) x", ""),
        ("SELECT 1 FROM t", ", LATERAL (SELECT 1) x", ""),
        ("INSERT INTO t VALUES (1)", ",(NULL, 'a', 1.5)", ""),
        ("UPDATE t SET a = 1", ", b = c->>'d'", ""),
    ] {
        let room = 40_000 - opening.len() - closing.len();
        let sql = format!("{opening}{}{closing}", part.repeat(room / part.len()));
        let (parsed, work) = measured(&sql).expect("tokens");
        parsed.unwrap_or_else(|err| panic!("{part}: {err}"));
        assert!(work.steps * 2 < work.allowance, "{part}: {work:?}");
    }
}

/// To the parser's own depth limit.
#[test]
fn ordinary_nesting_stays_well_within() {
    for (opening, closing) in [
        ("(", ")"),
        ("f(", ")"),
        ("coalesce(a, ", ")"),
        ("CASE WHEN a THEN ", " END"),
        ("CASE WHEN a THEN b ELSE ", " END"),
        ("CAST(", " AS int)"),
        ("NOT (", ")"),
        ("ARRAY[", "]"),
        ("EXISTS(SELECT ", ")"),
        ("(SELECT ", " FROM t)"),
        ("a IN (SELECT ", " FROM t)"),
        ("a IN (", ")"),
        ("position(a, ", ")"),
        ("substring(", " from 1 for 2)"),
        ("trim(both 'x' from ", ")"),
        ("extract(epoch from ", ")"),
        ("jsonb_build_object('a', ", ")"),
        ("(a = 1 OR b AND ", ")"),
        ("(a::int + ", ")"),
        ("sum(", ") OVER (PARTITION BY a)"),
    ] {
        // As deep as the parser reads it without a budget.
        let unmetered = |sql: &String| Parser::parse_sql(&PostgreSqlDialect {}, sql).is_ok();
        let deepest = (1..60)
            .map(|levels| nested(opening, "a", closing, levels))
            .take_while(unmetered)
            .last()
            .unwrap_or_else(|| panic!("{opening} is never read"));
        let (parsed, work) = measured(&deepest).expect("tokens");
        assert!(parsed.is_ok(), "{opening}: {parsed:?}");
        assert!(work.steps * 2 < work.allowance, "{opening}: {work:?}");
    }
}
