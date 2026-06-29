//! AST-level guard against non-read-only SQL. Defense in depth on top of the
//! Postgres role being read-only — if a DBA accidentally grants write
//! privileges to the `*_ro` role, the gateway still refuses to send a write
//! query to the DB.
//!
//! The contract: `is_read_only(sql)` parses the SQL with the Postgres
//! dialect and accepts only:
//!
//! - a single `SELECT` (with or without CTEs), recursively read-only
//! - a single non-`ANALYZE` `EXPLAIN` wrapping one of the above
//!
//! Everything else — multiple statements, `SELECT ... FOR UPDATE/SHARE`,
//! `SELECT ... INTO`, a write hidden in a CTE or subquery, `EXPLAIN ANALYZE`
//! (which executes), DDL, `GRANT/REVOKE`, transaction control, anything we
//! don't recognise — is rejected with a typed error. Conservative on purpose:
//! better to reject a legitimate exotic SELECT than quietly allow a write.

use sqlparser::ast::{Query, SetExpr, Statement};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("could not parse SQL")]
    Parse,
    #[error("multiple statements are not allowed (got {0})")]
    MultiStatement(usize),
    #[error("statement type `{0}` is not allowed; only SELECT and EXPLAIN")]
    NotAllowed(&'static str),
    #[error("SELECT ... FOR UPDATE/SHARE is not allowed (acquires write locks)")]
    Locking,
    #[error("write statement `{0}` is not allowed inside a read-only query")]
    WriteInReadPath(&'static str),
    #[error("SELECT ... INTO is not allowed (it materializes a table)")]
    SelectInto,
    #[error("EXPLAIN ANALYZE is not allowed (it executes the query)")]
    ExplainAnalyze,
}

pub fn is_read_only(sql: &str) -> Result<(), GuardError> {
    let dialect = PostgreSqlDialect {};
    let statements = Parser::parse_sql(&dialect, sql).map_err(|e| match e {
        ParserError::ParserError(_)
        | ParserError::TokenizerError(_)
        | ParserError::RecursionLimitExceeded => GuardError::Parse,
    })?;

    match statements.len() {
        0 => return Err(GuardError::Parse),
        1 => {}
        n => return Err(GuardError::MultiStatement(n)),
    }

    check_statement(&statements[0])
}

fn check_statement(stmt: &Statement) -> Result<(), GuardError> {
    match stmt {
        Statement::Query(query) => check_query(query),
        // EXPLAIN ANALYZE *executes* its target (so it would run a writable CTE),
        // unlike plain EXPLAIN which only plans — reject it outright.
        Statement::Explain { analyze: true, .. } => Err(GuardError::ExplainAnalyze),
        Statement::Explain { statement, .. } => check_statement(statement),
        Statement::ExplainTable { .. } => Ok(()), // `\d table` analog; read-only
        // Explicitly call out the families we reject so the error message is
        // useful — a single catch-all would say "Statement" for everything.
        Statement::Insert { .. } => Err(GuardError::NotAllowed("INSERT")),
        Statement::Update { .. } => Err(GuardError::NotAllowed("UPDATE")),
        Statement::Delete { .. } => Err(GuardError::NotAllowed("DELETE")),
        Statement::Truncate { .. } => Err(GuardError::NotAllowed("TRUNCATE")),
        Statement::Drop { .. } => Err(GuardError::NotAllowed("DROP")),
        Statement::CreateTable { .. } => Err(GuardError::NotAllowed("CREATE TABLE")),
        Statement::CreateView { .. } => Err(GuardError::NotAllowed("CREATE VIEW")),
        Statement::CreateIndex { .. } => Err(GuardError::NotAllowed("CREATE INDEX")),
        Statement::CreateSchema { .. } => Err(GuardError::NotAllowed("CREATE SCHEMA")),
        Statement::CreateDatabase { .. } => Err(GuardError::NotAllowed("CREATE DATABASE")),
        Statement::CreateFunction { .. } => Err(GuardError::NotAllowed("CREATE FUNCTION")),
        Statement::CreateRole { .. } => Err(GuardError::NotAllowed("CREATE ROLE")),
        Statement::AlterTable { .. } => Err(GuardError::NotAllowed("ALTER TABLE")),
        Statement::Grant { .. } => Err(GuardError::NotAllowed("GRANT")),
        Statement::Revoke { .. } => Err(GuardError::NotAllowed("REVOKE")),
        Statement::StartTransaction { .. } => Err(GuardError::NotAllowed("BEGIN/START")),
        Statement::Commit { .. } => Err(GuardError::NotAllowed("COMMIT")),
        Statement::Rollback { .. } => Err(GuardError::NotAllowed("ROLLBACK")),
        Statement::SetTransaction { .. } => Err(GuardError::NotAllowed("SET TRANSACTION")),
        Statement::SetVariable { .. } => Err(GuardError::NotAllowed("SET")),
        Statement::Copy { .. } => Err(GuardError::NotAllowed("COPY")),
        _ => Err(GuardError::NotAllowed("unsupported")),
    }
}

fn check_query(query: &Query) -> Result<(), GuardError> {
    // SELECT ... FOR UPDATE / FOR SHARE acquires write locks even though it's
    // syntactically a SELECT. Read-only roles can't take those locks anyway,
    // so the query would fail at the DB — but the rejection should happen
    // here with a clean error, not as a cryptic "permission denied" from PG.
    if !query.locks.is_empty() {
        return Err(GuardError::Locking);
    }
    // A data-modifying CTE (`WITH x AS (INSERT ... RETURNING ...)`) hides the
    // write behind a SELECT body — walk each CTE's inner query too.
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            check_query(&cte.query)?;
        }
    }
    check_set_expr(&query.body)
}

fn check_set_expr(body: &SetExpr) -> Result<(), GuardError> {
    match body {
        // `SELECT ... INTO new_table` materializes a table — DDL, not a read.
        SetExpr::Select(select) if select.into.is_some() => Err(GuardError::SelectInto),
        SetExpr::Select(_) | SetExpr::Values(_) | SetExpr::Table(_) => Ok(()),
        SetExpr::Query(inner) => check_query(inner),
        SetExpr::SetOperation { left, right, .. } => {
            check_set_expr(left)?;
            check_set_expr(right)
        }
        SetExpr::Insert(_) => Err(GuardError::WriteInReadPath("INSERT")),
        SetExpr::Update(_) => Err(GuardError::WriteInReadPath("UPDATE")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(sql: &str) {
        assert!(
            is_read_only(sql).is_ok(),
            "expected `{sql}` to be allowed, got {:?}",
            is_read_only(sql)
        );
    }

    fn rejected(sql: &str, want: GuardError) {
        let got = is_read_only(sql);
        assert_eq!(
            got,
            Err(want.clone()),
            "expected `{sql}` rejected as {want:?}, got {got:?}"
        );
    }

    fn rejected_not_allowed(sql: &str, kind: &str) {
        match is_read_only(sql) {
            Err(GuardError::NotAllowed(got)) => assert_eq!(got, kind, "for `{sql}`"),
            other => panic!("expected NotAllowed({kind}) for `{sql}`, got {other:?}"),
        }
    }

    #[test]
    fn plain_selects_allowed() {
        ok("SELECT 1");
        ok("SELECT id, email FROM users");
        ok("SELECT * FROM users WHERE id = 1");
        ok("SELECT a, b FROM t ORDER BY a LIMIT 10");
        ok("SELECT now()");
    }

    #[test]
    fn ctes_allowed() {
        ok("WITH x AS (SELECT 1) SELECT * FROM x");
        ok(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 5) SELECT * FROM n",
        );
    }

    #[test]
    fn explain_wrapping_select_allowed() {
        ok("EXPLAIN SELECT 1");
        ok("EXPLAIN (FORMAT JSON) SELECT * FROM users");
    }

    #[test]
    fn explain_analyze_rejected() {
        // ANALYZE *executes* the target, so it must not reach the DB — even when
        // the target is a plain SELECT, and especially for a writable CTE.
        rejected("EXPLAIN ANALYZE SELECT 1", GuardError::ExplainAnalyze);
        rejected(
            "EXPLAIN ANALYZE WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            GuardError::ExplainAnalyze,
        );
    }

    #[test]
    fn writable_cte_rejected() {
        rejected(
            "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            GuardError::WriteInReadPath("INSERT"),
        );
        rejected(
            "WITH x AS (UPDATE t SET a = 1 RETURNING id) SELECT * FROM x",
            GuardError::WriteInReadPath("UPDATE"),
        );
    }

    #[test]
    fn select_into_rejected() {
        rejected("SELECT * INTO new_table FROM t", GuardError::SelectInto);
    }

    #[test]
    fn write_nested_in_body_rejected() {
        // Write buried in a parenthesised subquery used as the outer body,
        // and a write in a CTE nested inside another CTE — both must recurse.
        rejected(
            "(WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x)",
            GuardError::WriteInReadPath("INSERT"),
        );
        rejected(
            "WITH a AS (WITH b AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM b) SELECT * FROM a",
            GuardError::WriteInReadPath("INSERT"),
        );
    }

    #[test]
    fn writes_rejected() {
        rejected_not_allowed("INSERT INTO users (id) VALUES (1)", "INSERT");
        rejected_not_allowed("UPDATE users SET email = 'x'", "UPDATE");
        rejected_not_allowed("DELETE FROM users", "DELETE");
        rejected_not_allowed("TRUNCATE users", "TRUNCATE");
    }

    #[test]
    fn ddl_rejected() {
        rejected_not_allowed("CREATE TABLE t (id int)", "CREATE TABLE");
        rejected_not_allowed("DROP TABLE users", "DROP");
        rejected_not_allowed("ALTER TABLE users ADD COLUMN x int", "ALTER TABLE");
    }

    #[test]
    fn grants_rejected() {
        rejected_not_allowed("GRANT SELECT ON users TO bob", "GRANT");
        rejected_not_allowed("REVOKE SELECT ON users FROM bob", "REVOKE");
    }

    #[test]
    fn transaction_control_rejected() {
        rejected_not_allowed("BEGIN", "BEGIN/START");
        rejected_not_allowed("COMMIT", "COMMIT");
        rejected_not_allowed("ROLLBACK", "ROLLBACK");
    }

    #[test]
    fn locking_select_rejected() {
        rejected("SELECT * FROM users FOR UPDATE", GuardError::Locking);
        rejected("SELECT * FROM users FOR SHARE", GuardError::Locking);
    }

    /// The classic injection trick: comment hides the real statement, then a
    /// second one tries to slip through. AST parsing sees both; we reject on
    /// statement count.
    #[test]
    fn multi_statement_rejected_even_if_first_is_select() {
        let sql = "SELECT 1; DELETE FROM users";
        let got = is_read_only(sql);
        assert!(
            matches!(got, Err(GuardError::MultiStatement(2))),
            "got {got:?}"
        );
    }

    /// `EXPLAIN DELETE FROM users` is still a DELETE-shaped statement —
    /// EXPLAIN without ANALYZE doesn't execute, but we reject anyway for
    /// consistency: the read-only role wouldn't permit it, and an operator
    /// might enable ANALYZE later thinking EXPLAIN is always safe.
    #[test]
    fn explain_of_a_write_rejected() {
        rejected_not_allowed("EXPLAIN DELETE FROM users", "DELETE");
        rejected_not_allowed("EXPLAIN (FORMAT JSON) UPDATE users SET x = 1", "UPDATE");
    }

    #[test]
    fn copy_rejected() {
        // COPY FROM is a write; COPY TO STDOUT is read but we're conservative.
        rejected_not_allowed("COPY users FROM '/tmp/foo'", "COPY");
        rejected_not_allowed("COPY users TO STDOUT", "COPY");
    }

    #[test]
    fn unparseable_rejected_as_parse_error() {
        assert!(matches!(is_read_only("SELEKT 1"), Err(GuardError::Parse)));
        assert!(matches!(is_read_only(""), Err(GuardError::Parse)));
        assert!(matches!(is_read_only("   "), Err(GuardError::Parse)));
    }
}

#[cfg(test)]
mod proptests {
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
    }
}
