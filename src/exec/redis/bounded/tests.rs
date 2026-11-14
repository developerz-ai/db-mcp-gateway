//! The argv rewrites: every range and count ends up at most `cap` elements,
//! and the semantics of an already-small request are kept.

use super::rewrite::*;

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn non_negative_index_ranges_are_clamped_without_a_length() {
    assert!(!needs_length(0, 999_999));
    assert_eq!(bounded_indices(0, 999_999, None, 11), (0, 10));
    assert_eq!(
        bounded_indices(5, 7, None, 11),
        (5, 7),
        "a small range is kept"
    );
    assert_eq!(
        bounded_indices(7, 5, None, 11),
        (1, 0),
        "an empty range stays empty"
    );
    assert_eq!(
        bounded_indices(i64::MAX - 1, i64::MAX, None, 11).0,
        i64::MAX - 1
    );
}

#[test]
fn negative_indices_resolve_against_the_length_first() {
    assert!(needs_length(0, -1));
    assert!(needs_length(-3, 10));
    // `0 -1` on a million elements → the first 11.
    assert_eq!(bounded_indices(0, -1, Some(1_000_000), 11), (0, 10));
    // The last three of ten.
    assert_eq!(bounded_indices(-3, -1, Some(10), 11), (7, 9));
    // A negative start past the front clamps to 0, like Redis.
    assert_eq!(bounded_indices(-50, -1, Some(10), 4), (0, 3));
    // Empty collection or inverted range → empty.
    assert_eq!(bounded_indices(0, -1, Some(0), 11), (1, 0));
    assert_eq!(bounded_indices(-1, -5, Some(10), 11), (1, 0));
}

#[test]
fn score_and_lex_ranges_get_a_limit() {
    assert_eq!(
        with_limit(&argv(&["z", "-inf", "+inf", "WITHSCORES"]), 11),
        argv(&["z", "-inf", "+inf", "WITHSCORES", "LIMIT", "0", "11"])
    );
    // A negative count is Redis' "all": clamped.
    assert_eq!(
        with_limit(&argv(&["z", "0", "9", "limit", "5", "-1"]), 11),
        argv(&["z", "0", "9", "limit", "5", "11"])
    );
    assert_eq!(
        with_limit(&argv(&["z", "0", "9", "LIMIT", "0", "999999"]), 11)[5],
        "11"
    );
    // A smaller count is kept.
    assert_eq!(
        with_limit(&argv(&["z", "[a", "[z", "LIMIT", "2", "3"]), 11)[5],
        "3"
    );
    // A min/max that reads "LIMIT" is a bound, not the option.
    assert_eq!(
        with_limit(&argv(&["LIMIT", "[LIMIT", "+"]), 11),
        argv(&["LIMIT", "[LIMIT", "+", "LIMIT", "0", "11"])
    );
}

#[test]
fn stream_ranges_get_a_count() {
    assert_eq!(
        with_count(&argv(&["s", "-", "+"]), 11),
        argv(&["s", "-", "+", "COUNT", "11"])
    );
    assert_eq!(
        with_count(&argv(&["s", "-", "+", "COUNT", "500"]), 11)[4],
        "11"
    );
    assert_eq!(
        with_count(&argv(&["s", "-", "+", "count", "4"]), 11)[4],
        "4"
    );
}

#[test]
fn lpos_count_zero_means_all_and_is_clamped_and_maxlen_is_bounded() {
    let out = lpos_bounded(&argv(&["l", "x", "COUNT", "0"]), 11);
    assert_eq!(out[3], "11");
    assert_eq!(out[4..], argv(&["MAXLEN", &LPOS_MAX_SCAN.to_string()]));
    let out = lpos_bounded(&argv(&["l", "x", "COUNT", "3", "MAXLEN", "0"]), 11);
    assert_eq!(
        out,
        argv(&["l", "x", "COUNT", "3", "MAXLEN", &LPOS_MAX_SCAN.to_string()])
    );
    let out = lpos_bounded(&argv(&["l", "x", "MAXLEN", "50"]), 11);
    assert_eq!(
        out,
        argv(&["l", "x", "MAXLEN", "50"]),
        "single answer, small scan"
    );
}

#[test]
fn random_counts_keep_their_sign_but_not_their_size() {
    assert_eq!(random_count(&argv(&["s", "-2000000000"]), 11)[1], "-11");
    assert_eq!(random_count(&argv(&["s", "2000000000"]), 11)[1], "11");
    assert_eq!(random_count(&argv(&["s", "-3"]), 11)[1], "-3");
    assert_eq!(random_count(&argv(&["s"]), 11), argv(&["s"]));
    assert_eq!(
        random_count(&argv(&["h", &i64::MIN.to_string(), "WITHVALUES"]), 11),
        argv(&["h", "-11", "WITHVALUES"])
    );
}

#[test]
fn getrange_length_follows_redis_arithmetic() {
    assert_eq!(getrange_len(100, 0, -1), 100);
    assert_eq!(getrange_len(100, 0, 9), 10);
    assert_eq!(getrange_len(100, -10, -1), 10);
    assert_eq!(getrange_len(100, 50, 10), 0);
    assert_eq!(getrange_len(100, 0, i64::MAX), 100);
    assert_eq!(getrange_len(0, 0, -1), 0);
}

#[test]
fn the_fitting_prefix_stops_before_the_budget_overflows() {
    assert_eq!(fitting_prefix(&[10, 20, 30], 30), 2);
    assert_eq!(fitting_prefix(&[10, 20, 30], 60), 3);
    assert_eq!(fitting_prefix(&[100], 30), 0);
    assert_eq!(fitting_prefix(&[], 30), 0);
}
