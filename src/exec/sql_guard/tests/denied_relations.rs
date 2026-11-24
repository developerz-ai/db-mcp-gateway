use super::*;

// --- Relations whose rows are other sessions' statement text ---

fn denied_as(sql: &str, want: &str) {
    match is_read_only(sql) {
        Err(GuardError::DeniedRelation(got)) => assert_eq!(got, want, "for `{sql}`"),
        other => panic!("expected DeniedRelation({want}) for `{sql}`, got {other:?}"),
    }
}

#[test]
fn session_statement_views_rejected() {
    for (sql, want) in [
        ("SELECT query FROM pg_stat_activity", "pg_stat_activity"),
        (
            "SELECT * FROM pg_catalog.pg_stat_activity",
            "pg_stat_activity",
        ),
        (r#"SELECT * FROM "pg_stat_activity""#, "pg_stat_activity"),
        ("SELECT * FROM PG_STAT_ACTIVITY a", "pg_stat_activity"),
        ("SELECT * FROM ONLY pg_stat_activity", "pg_stat_activity"),
        ("SELECT * FROM pg_stat_statements", "pg_stat_statements"),
        (
            "SELECT * FROM public.pg_stat_statements_info",
            "pg_stat_statements_info",
        ),
        (
            "SELECT statement FROM pg_prepared_statements",
            "pg_prepared_statements",
        ),
        ("SELECT * FROM pg_stat_monitor", "pg_stat_monitor"),
        (
            "SELECT * FROM yb_terminated_queries",
            "yb_terminated_queries",
        ),
        (
            "SELECT * FROM pg_stat_statements(true)",
            "pg_stat_statements",
        ),
        ("SELECT * FROM ONLY (pg_stat_activity)", "pg_stat_activity"),
        ("SELECT * FROM pg_stat_activity *", "pg_stat_activity"),
        (
            "SELECT (a).query FROM pg_stat_activity a",
            "pg_stat_activity",
        ),
    ] {
        denied_as(sql, want);
    }
}

#[test]
fn session_statement_views_rejected_in_every_from_position() {
    for sql in [
        "SELECT 1 FROM t JOIN pg_stat_activity a ON a.pid = t.pid",
        "SELECT 1 FROM t, LATERAL (SELECT query FROM pg_stat_activity) a",
        "SELECT (SELECT query FROM pg_stat_activity LIMIT 1)",
        "SELECT 1 WHERE EXISTS (SELECT 1 FROM pg_stat_activity)",
        "WITH a AS (SELECT * FROM pg_stat_activity) SELECT * FROM a",
        "SELECT 1 UNION ALL SELECT pid FROM pg_stat_activity",
        "EXPLAIN SELECT * FROM pg_stat_activity",
    ] {
        denied_as(sql, "pg_stat_activity");
    }
}

#[test]
fn session_statement_views_rejected_in_write_mode() {
    for sql in [
        "INSERT INTO t SELECT query FROM pg_stat_activity",
        "UPDATE t SET q = a.query FROM pg_stat_activity a WHERE a.pid = t.pid",
        "DELETE FROM t USING pg_stat_activity a WHERE a.pid = t.pid",
    ] {
        assert_eq!(
            check_sql(sql, Access::ReadWrite),
            Err(GuardError::DeniedRelation("pg_stat_activity")),
            "for `{sql}`"
        );
    }
}

/// Statistics without statement text stay readable, and the name is only
/// refused as a word — never inside a longer name or a string.
#[test]
fn other_statistics_views_still_allowed() {
    ok("SELECT * FROM pg_stat_user_tables");
    ok("SELECT * FROM pg_stat_database");
    ok("SELECT * FROM pg_locks");
    ok("SELECT * FROM my_pg_stat_activity");
    ok("SELECT * FROM pg_views WHERE viewname = 'pg_stat_activity'");
}

#[test]
fn refusal_points_at_db_activity() {
    let msg = is_read_only("SELECT * FROM pg_stat_activity")
        .expect_err("refused")
        .to_string();
    assert!(msg.contains("db_activity"), "{msg}");
}
