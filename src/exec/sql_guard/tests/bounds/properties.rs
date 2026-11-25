use proptest::prelude::*;

use super::*;

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
