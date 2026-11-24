//! `run_query` unit tests: the indeterminate-write note and the Redis,
//! Mongo and SQL gates at the tool edge.

use super::*;
use crate::tools::audit_dispatch::{Reply, error_outcome};

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

#[test]
fn a_malformed_mongo_command_is_invalid_arguments() {
    for command in ["{\"find\": ", "[]", "{}", "\"find\""] {
        let outcome = *mongo_access(Value::from(1), command).expect_err(command);
        assert_eq!(outcome.code, OutcomeCode::InvalidArguments, "{command}");
    }
}

/// A well-formed command the policy refuses is left to the adapter, which
/// refuses it `forbidden_sql`; an allowed one reads.
#[test]
fn a_well_formed_mongo_command_passes_the_edge() {
    for command in [r#"{"find": "users"}"#, r#"{"insert": "users"}"#] {
        assert_eq!(
            mongo_access(Value::from(1), command).ok(),
            Some(Access::ReadOnly),
            "{command}"
        );
    }
}

#[test]
fn an_unparseable_statement_carries_its_location() {
    let outcome = *statement_access("SELECT 1\nFROM t WHERE = = 1", false).expect_err("parse");
    assert_eq!(outcome.code, OutcomeCode::ForbiddenSql);
    let Reply::Unparsed(location) = outcome.reply else {
        panic!("no location: {:?}", outcome.reply);
    };
    assert_eq!(location.line, 2);
    let refused = *statement_access("DROP TABLE t", false).expect_err("DROP");
    assert!(
        matches!(refused.reply, Reply::ToolError),
        "{:?}",
        refused.reply
    );
}
