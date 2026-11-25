use proptest::prelude::*;
use proptest::test_runner::RngSeed;

use super::*;
use crate::exec::sql_guard::bounds::with_parser_stack;

const OPENINGS: &[&str] = &[
    "NOT ",
    "NOT (a).",
    "CAST(",
    "CAST(a.",
    "(",
    "(a).",
    "f(",
    "f(a.",
    "a.",
    "CASE ",
    "CASE WHEN a THEN ",
    "CASE a.",
    "ARRAY[",
    "ARRAY[a.",
    "a[",
    "EXISTS(SELECT ",
    "(SELECT ",
    "a IN (",
    "a IN (SELECT ",
    "INTERVAL ",
    "INTERVAL a.",
    "DATE ",
    "POSITION(",
    "POSITION(a.",
    "EXTRACT(a FROM ",
    "TRIM(a FROM ",
    "OVERLAY(",
    "SUBSTRING(",
    "IF(",
    "ROW(",
    "a::",
    "a + ",
    "- ",
    "a AND ",
    "f(a => ",
    "a = ANY(",
    "XMLELEMENT(NAME a, ",
    "JSON_OBJECT('a': ",
    "a AT TIME ZONE ",
    "a COLLATE ",
    "\"a\".",
    "SELECT ",
    "SELECT * FROM (",
    "SELECT * FROM ((SELECT 1) JOIN ",
    "WITH a AS (",
    "((SELECT 1) UNION ",
    "LATERAL (",
    "a, ",
    "1 ",
    "'a' ",
    "$1 ",
];
const CLOSINGS: &[&str] = &[
    "",
    ")",
    "]",
    " END",
    " AS int)",
    " THEN a END",
    ") x",
    " FROM t)",
    ".b",
    " ON a)",
];

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        rng_seed: RngSeed::Fixed(0x6262_7567),
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Any nest of any openings: the parse ends at its allowance or before,
    /// within a time that says the steps it counts are the work it does.
    #[test]
    fn nested_prefixes_end_within_the_budget(
        unit in proptest::collection::vec(proptest::sample::select(OPENINGS), 1..4),
        levels in 1usize..60,
        closing in proptest::collection::vec(proptest::sample::select(CLOSINGS), 1..3),
        closed in 0usize..60,
        leaf in proptest::sample::select(vec!["a", "1", "'x'", "", "a.b", "(a)", "NOT", "x y z"]),
    ) {
        let sql = format!("SELECT {}{leaf}{}", unit.concat().repeat(levels), closing.concat().repeat(closed));
        prop_assume!(sql.len() <= MAX_SQL_BYTES);
        let what = format!("{unit:?} x {levels}");
        let (verdict, parsed) = soon(SOON, &what, move || {
            let verdict = is_read_only(&sql);
            (verdict, with_parser_stack(|| {
                measured(&sql).map(|(parsed, work)| (parsed.map(drop), work))
            }))
        });
        if let Ok((parsed, work)) = parsed {
            let spent = parsed == Err(GuardError::TooMuchWork { limit: work.allowance });
            prop_assert_eq!(spent, work.steps > work.allowance, "{:?}", work);
            prop_assert!(!spent || verdict.is_err(), "{}", what);
        }
    }
}
