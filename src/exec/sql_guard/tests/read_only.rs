use super::*;

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
    ok("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 5) SELECT * FROM n");
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

/// The parenthesised utility-option form is the *other* spelling of the same
/// flag, and it is the one the Postgres dialect parses into `options` with
/// `analyze: false` — so a keyword-only check lets it through and the DB
/// runs the query in full, row cap and all bypassed.
#[test]
fn explain_with_analyze_utility_option_rejected() {
    rejected("EXPLAIN (ANALYZE) SELECT 1", GuardError::ExplainAnalyze);
    rejected(
        "EXPLAIN (ANALYZE, FORMAT JSON) SELECT 1",
        GuardError::ExplainAnalyze,
    );
    rejected(
        "EXPLAIN (VERBOSE, ANALYZE) SELECT * FROM users",
        GuardError::ExplainAnalyze,
    );
    // Option names are identifiers — match them case-insensitively.
    rejected("EXPLAIN (analyze) SELECT 1", GuardError::ExplainAnalyze);
    rejected("EXPLAIN (AnAlYzE) SELECT 1", GuardError::ExplainAnalyze);
    // Argument form: still executes when true, and we don't interpret args.
    rejected(
        "EXPLAIN (ANALYZE true) SELECT 1",
        GuardError::ExplainAnalyze,
    );
    rejected(
        "EXPLAIN (ANALYZE) WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
        GuardError::ExplainAnalyze,
    );
}

#[test]
fn explain_without_analyze_still_allowed() {
    // The fix must not turn every parenthesised EXPLAIN into a rejection.
    ok("EXPLAIN SELECT 1");
    ok("EXPLAIN (FORMAT JSON) SELECT 1");
    ok("EXPLAIN (VERBOSE) SELECT 1");
    ok("EXPLAIN (COSTS false, FORMAT TEXT) SELECT * FROM users");
}

/// Nested `EXPLAIN` never reaches the guard's shape check: the Postgres
/// dialect rejects it at parse time with `"Explain must be root of the
/// plan"`, matching Postgres itself. The unwrap `while` loop in
/// [`check_sql`] therefore only ever iterates once today — it stays a
/// loop (rather than an `if let`) as defense-in-depth for any future
/// dialect that admits nested `EXPLAIN`, so ANALYZE at any wrapper depth
/// would still be caught before the DB is touched.
#[test]
fn nested_explain_rejected_at_parse_time() {
    assert!(matches!(
        is_read_only("EXPLAIN EXPLAIN ANALYZE SELECT 1"),
        Err(GuardError::Parse)
    ));
    assert!(matches!(
        is_read_only("EXPLAIN EXPLAIN (ANALYZE) SELECT 1"),
        Err(GuardError::Parse)
    ));
    assert!(matches!(
        is_read_only("EXPLAIN EXPLAIN DELETE FROM users"),
        Err(GuardError::Parse)
    ));
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

/// sqlparser 0.55+ folds every `SET` form into `Statement::Set(Set)`; the
/// guard must still name the family rather than fall to "unsupported".
#[test]
fn set_statements_rejected_by_family() {
    rejected_not_allowed(
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "SET TRANSACTION",
    );
    rejected_not_allowed("SET search_path = public", "SET");
    rejected_not_allowed("SET ROLE postgres", "SET");
    rejected_not_allowed("SET SESSION AUTHORIZATION postgres", "SET");
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

#[test]
fn guarded_sql_mirrors_the_guard_and_names_the_access_needed() {
    let sql = "SELECT id FROM users";
    let read = GuardedSql::parse(sql, Access::ReadOnly).expect("read");
    assert_eq!(read.as_str(), sql);
    assert_eq!(read.required_access(), Access::ReadOnly);
    assert_eq!(
        GuardedSql::parse("DELETE FROM users", Access::ReadOnly),
        Err(GuardError::NotAllowed("DELETE"))
    );
    // A write grant does not make a read need the write role.
    let read = GuardedSql::parse(sql, Access::ReadWrite).expect("read");
    assert_eq!(read.required_access(), Access::ReadOnly);
    let write = GuardedSql::parse("DELETE FROM users", Access::ReadWrite).expect("write");
    assert_eq!(write.required_access(), Access::ReadWrite);
}
