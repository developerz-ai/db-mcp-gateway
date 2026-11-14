//! `run_query` unit tests: the indeterminate-write note and the Redis
//! argv gate.

use super::*;

#[test]
fn a_timed_out_write_says_it_may_have_committed() {
    let mut outcome = error_outcome(OutcomeCode::Timeout, ERROR_MESSAGES.timeout);
    note_indeterminate_write(&mut outcome, false);
    let message = outcome.error_message.unwrap_or_default();
    assert!(message.contains(WRITE_MAY_HAVE_COMMITTED), "{message}");
}

#[test]
fn a_cancelled_write_says_it_may_have_committed() {
    let mut outcome = error_outcome(
        OutcomeCode::Cancelled,
        "query was cancelled by cancel_query",
    );
    note_indeterminate_write(&mut outcome, false);
    let message = outcome.error_message.unwrap_or_default();
    assert!(message.contains(WRITE_MAY_HAVE_COMMITTED), "{message}");
}

#[test]
fn a_rejected_write_is_not_called_indeterminate() {
    let mut outcome = error_outcome(OutcomeCode::SyntaxError, ERROR_MESSAGES.sql_rejected);
    note_indeterminate_write(&mut outcome, false);
    assert_eq!(
        outcome.error_message.as_deref(),
        Some(ERROR_MESSAGES.sql_rejected)
    );
}

#[test]
fn a_dry_run_write_is_never_called_indeterminate() {
    // A dry_run rolls the transaction back (exec/pg/run.rs), so even a
    // cut-off one cannot have committed anything.
    let mut outcome = error_outcome(OutcomeCode::Timeout, ERROR_MESSAGES.timeout);
    note_indeterminate_write(&mut outcome, true);
    assert_eq!(
        outcome.error_message.as_deref(),
        Some(ERROR_MESSAGES.timeout)
    );
}

#[test]
fn a_malformed_redis_argv_is_invalid_arguments() {
    for argv in ["GET k", "[]", r#"["GET", {"k": 1}]"#, r#"["SCAN"]"#] {
        let outcome = *redis_access(Value::from(1), argv).expect_err(argv);
        assert_eq!(outcome.code, OutcomeCode::InvalidArguments, "{argv}");
    }
}

#[test]
fn a_refused_redis_command_is_forbidden_sql_naming_it() {
    let outcome = *redis_access(Value::from(1), r#"["set","k","v"]"#).expect_err("SET");
    assert_eq!(outcome.code, OutcomeCode::ForbiddenSql);
    let message = outcome.error_message.unwrap_or_default();
    assert!(message.contains("`set`"), "{message}");
    assert!(message.contains("read-only allowlist"), "{message}");
}

#[test]
fn an_allowed_redis_command_reads() {
    assert_eq!(
        redis_access(Value::from(1), r#"["hgetall","user:1"]"#).ok(),
        Some(Access::ReadOnly)
    );
}
