use super::*;

// --- Write mode (Access::ReadWrite) -------------------------------------

fn ok_write(sql: &str) {
    let got = check_sql(sql, Access::ReadWrite);
    assert!(
        got.is_ok(),
        "expected `{sql}` allowed for writes, got {got:?}"
    );
}

fn rejected_write_not_allowed(sql: &str, kind: &str) {
    match check_sql(sql, Access::ReadWrite) {
        Err(GuardError::NotAllowed(got)) => assert_eq!(got, kind, "for `{sql}`"),
        other => panic!("expected NotAllowed({kind}) for `{sql}`, got {other:?}"),
    }
}

fn rejected_write(sql: &str, want: GuardError) {
    let got = check_sql(sql, Access::ReadWrite);
    assert_eq!(
        got,
        Err(want.clone()),
        "expected `{sql}` rejected as {want:?}, got {got:?}"
    );
}

fn rejected_write_denied(sql: &str, fn_name: &str) {
    match check_sql(sql, Access::ReadWrite) {
        Err(GuardError::DeniedFunction(got)) => assert_eq!(got, fn_name, "for `{sql}`"),
        other => panic!("expected DeniedFunction({fn_name}) for `{sql}`, got {other:?}"),
    }
}

#[test]
fn write_mode_allows_data_writes() {
    ok_write("INSERT INTO users (id, email) VALUES (1, 'a@b.c')");
    ok_write("INSERT INTO archive SELECT * FROM users WHERE active = false");
    ok_write("UPDATE users SET email = 'x@y.z' WHERE id = 1");
    ok_write("DELETE FROM users WHERE id = 1");
    ok_write("INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = 2");
    ok_write("INSERT INTO t (id) VALUES (1) ON CONFLICT DO NOTHING");
    ok_write("DELETE FROM users WHERE id = 1 RETURNING id, email");
}

#[test]
fn write_mode_still_allows_reads() {
    // Read is a subset of read-write — a `query_write` caller can still SELECT.
    ok_write("SELECT id, email FROM users WHERE id = 1");
    ok_write("WITH x AS (SELECT 1) SELECT * FROM x");
    ok_write("EXPLAIN SELECT 1");
}

/// `EXPLAIN` without `ANALYZE` does not execute; once the wrapper is
/// peeled, the shape check sees a write statement and the ReadWrite grant
/// covers it. ANALYZE still executes and stays rejected — the write grant
/// must not become a way to bypass the row cap.
#[test]
fn write_mode_allows_explain_of_a_write() {
    ok_write("EXPLAIN INSERT INTO t VALUES (1)");
    ok_write("EXPLAIN (FORMAT JSON) UPDATE users SET x = 1");
    ok_write("EXPLAIN DELETE FROM users WHERE id = 1");
    rejected_write(
        "EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
        GuardError::ExplainAnalyze,
    );
    rejected_write(
        "EXPLAIN (ANALYZE) DELETE FROM users",
        GuardError::ExplainAnalyze,
    );
}

#[test]
fn write_mode_still_blocks_schema_mods() {
    // "write data, no schema mods" — DDL and privilege ops stay blocked
    // even with a write grant.
    rejected_write_not_allowed("TRUNCATE users", "TRUNCATE");
    rejected_write_not_allowed("DROP TABLE users", "DROP");
    rejected_write_not_allowed("CREATE TABLE t (id int)", "CREATE TABLE");
    rejected_write_not_allowed("ALTER TABLE users ADD COLUMN x int", "ALTER TABLE");
    rejected_write_not_allowed("GRANT SELECT ON users TO bob", "GRANT");
    rejected_write_not_allowed("REVOKE SELECT ON users FROM bob", "REVOKE");
    rejected_write_not_allowed("COPY users FROM '/tmp/foo'", "COPY");
    rejected_write_not_allowed("BEGIN", "BEGIN/START");
}

#[test]
fn write_mode_still_rejects_multi_statement() {
    // A write can't ride in behind another statement.
    assert!(matches!(
        check_sql("DELETE FROM users; DROP TABLE users", Access::ReadWrite),
        Err(GuardError::MultiStatement(2))
    ));
    assert!(matches!(
        check_sql(
            "INSERT INTO t VALUES (1); INSERT INTO t VALUES (2)",
            Access::ReadWrite
        ),
        Err(GuardError::MultiStatement(2))
    ));
}

#[test]
fn write_mode_still_blocks_denied_functions() {
    // Filesystem/network functions stay denied in every read position of a
    // write statement.
    rejected_write_denied(
        "INSERT INTO t (data) VALUES (pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
    rejected_write_denied(
        "INSERT INTO t SELECT pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
    rejected_write_denied(
        "UPDATE t SET data = pg_read_file('/etc/passwd') WHERE id = 1",
        "pg_read_file",
    );
    rejected_write_denied(
        "DELETE FROM t WHERE data = pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
    rejected_write_denied(
        "DELETE FROM t WHERE id = 1 RETURNING pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
    rejected_write_denied(
        "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET data = pg_read_file('/x')",
        "pg_read_file",
    );
}

#[test]
fn write_mode_rejects_write_hidden_in_select_body() {
    // Write mode widens to a *top-level* INSERT/UPDATE/DELETE only. A write
    // buried in a SELECT's CTE stays rejected — the top-level statement is a
    // Query, which is always walked read-only. Use a plain write instead.
    rejected_write(
        "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
        GuardError::WriteInReadPath("INSERT"),
    );
    rejected_write(
        "WITH x AS (UPDATE t SET a = 1 RETURNING id) SELECT * FROM x",
        GuardError::WriteInReadPath("UPDATE"),
    );
}

#[test]
fn read_mode_rejects_writes_write_mode_gates_them() {
    // The same INSERT: rejected under ReadOnly, allowed under ReadWrite.
    assert!(matches!(
        check_sql("INSERT INTO t VALUES (1)", Access::ReadOnly),
        Err(GuardError::NotAllowed("INSERT"))
    ));
    assert!(check_sql("INSERT INTO t VALUES (1)", Access::ReadWrite).is_ok());
}
