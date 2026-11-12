//! Random hammer: the guard must never panic, never allow a write-shaped
//! statement, and never crash on garbage input. Doesn't try to be a
//! complete grammar — just throws shapes at it.

use super::*;
use proptest::prelude::*;

fn arbitrary_safe_select() -> impl Strategy<Value = String> {
    proptest::sample::select(&[
        "SELECT 1",
        "SELECT id FROM t",
        "SELECT * FROM users WHERE id = 1",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "EXPLAIN SELECT 1",
        "EXPLAIN (FORMAT JSON) SELECT now()",
    ])
    .prop_map(|s| s.to_string())
}

fn arbitrary_write_or_ddl() -> impl Strategy<Value = String> {
    proptest::sample::select(&[
        "INSERT INTO t VALUES (1)",
        "UPDATE t SET x = 1",
        "DELETE FROM t",
        "TRUNCATE t",
        "DROP TABLE t",
        "ALTER TABLE t ADD COLUMN y int",
        "CREATE TABLE t (id int)",
        "GRANT SELECT ON t TO bob",
        "REVOKE SELECT ON t FROM bob",
    ])
    .prop_map(|s| s.to_string())
}

fn arbitrary_denied_function() -> impl Strategy<Value = String> {
    proptest::sample::select(&[
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_read_binary_file('/etc/shadow')",
        "SELECT pg_ls_dir('/tmp')",
        "SELECT pg_stat_file('/etc/passwd')",
        "SELECT lo_export(1, '/tmp/x')",
        "SELECT lo_import('/etc/passwd')",
    ])
    .prop_map(|s| s.to_string())
}

proptest! {
    #[test]
    fn never_panics_on_arbitrary_strings(s in ".{0,200}") {
        // We don't care about the result — just that the parser path
        // never aborts. RecursionLimitExceeded is fine; it's a typed
        // GuardError::Parse, not a panic.
        let _ = is_read_only(&s);
    }

    #[test]
    fn safe_selects_always_allowed(sql in arbitrary_safe_select()) {
        prop_assert!(is_read_only(&sql).is_ok(), "rejected: {sql}");
    }

    #[test]
    fn writes_always_rejected(sql in arbitrary_write_or_ddl()) {
        prop_assert!(
            matches!(is_read_only(&sql), Err(GuardError::NotAllowed(_))),
            "wrongly allowed: {sql}"
        );
    }

    /// Combining safe + unsafe via `;` always rejects on MultiStatement
    /// regardless of order — never short-circuits to "first one was OK".
    #[test]
    fn safe_then_unsafe_rejected(safe in arbitrary_safe_select(), unsafe_ in arbitrary_write_or_ddl()) {
        let combined = format!("{safe}; {unsafe_}");
        let got = is_read_only(&combined);
        prop_assert!(
            matches!(got, Err(GuardError::MultiStatement(_)) | Err(GuardError::NotAllowed(_)) | Err(GuardError::Parse)),
            "wrongly handled: `{combined}` → {got:?}"
        );
    }

    #[test]
    fn denied_functions_always_rejected(sql in arbitrary_denied_function()) {
        prop_assert!(
            matches!(is_read_only(&sql), Err(GuardError::DeniedFunction(_))),
            "wrongly allowed: {sql}"
        );
    }
}
