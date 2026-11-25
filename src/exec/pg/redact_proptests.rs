//! The configured role never reaches the agent through a Postgres rejection.
//! Postgres names a role double-quoted (`permission denied to set role
//! "app"`); the message a rejection keeps is the gateway's wording plus at
//! most a name cut from the caller's SQL, and the hint is the server's text —
//! both pass through the role redaction, whatever surrounds the role.

use proptest::prelude::*;

use super::{rejection_message, safe_hint};
use crate::exec::DbRejection;

/// A role name the config accepts (`validate_role`).
fn role() -> impl Strategy<Value = String> {
    "[A-Za-z_][A-Za-z0-9_]{0,15}"
}

/// Arbitrary text without a double quote: a quote next to the planted
/// `"role"` would make it a different quoted identifier, not the role.
fn filler() -> impl Strategy<Value = String> {
    "[^\"\\p{C}]{0,24}"
}

/// Parse/analysis SQLSTATEs whose message names the identifier at the
/// error position, plus run-time ones that name nothing.
fn sqlstate() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "42P01", "42601", "42883", "42703", "42501", "42704", "22P02", "P0001",
    ])
}

/// What `pg::error::rejection` builds from a refused statement.
fn rejection(sqlstate: &str, position: usize, sql: &str, hint: &str, role: &str) -> DbRejection {
    let at = Some(position);
    DbRejection::new(sqlstate, &rejection_message(sqlstate, at, sql), role)
        .with_position(at)
        .with_hint(safe_hint(sqlstate, at, sql, Some(hint)), role)
}

proptest! {
    #[test]
    fn the_quoted_role_never_survives(
        role in role(),
        sqlstate in sqlstate(),
        (sql_before, sql_after) in (filler(), filler()),
        (hint_before, hint_after) in (filler(), filler()),
        position in 1..64usize,
        qualifier in prop::sample::select(vec!["", "public.", "\"My Schema\"."]),
    ) {
        let quoted = format!("\"{role}\"");
        let sql = format!("{sql_before}{qualifier}{quoted}{sql_after}");
        let hint = format!("{hint_before}{quoted}{hint_after}");
        let r = rejection(sqlstate, position, &sql, &hint, &role);
        prop_assert!(!r.message().contains(&quoted), "message: {}", r.message());
        prop_assert!(
            !r.hint().is_some_and(|h| h.contains(&quoted)),
            "hint: {:?}",
            r.hint()
        );
    }

    /// Non-triviality: with the error position on the planted role, the
    /// name is echoed — redacted — and so is the hint.
    #[test]
    fn a_role_at_the_error_position_is_echoed_redacted(
        role in role(),
        before in filler(),
        hint_text in filler(),
        tail in "( [a-z ,()]{0,12})?",
        qualifier in prop::sample::select(vec!["", "public.", "\"My Schema\"."]),
    ) {
        let sql = format!("{before} {qualifier}\"{role}\"{tail}");
        let position = before.chars().count() + 2;
        let r = rejection("42P01", position, &sql, &format!("{hint_text} \"{role}\""), &role);
        let want = format!("relation does not exist: {qualifier}\"<role>\"");
        prop_assert_eq!(r.message(), want.as_str());
        prop_assert!(r.hint().is_some_and(|h| h.ends_with("\"<role>\"")), "{:?}", r.hint());
    }
}
