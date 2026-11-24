use super::*;

// --- Attribute notation: Postgres resolves `(x).f` and `row.f` to a call
// --- of `f` when no such column exists, with no parentheses in the text.

fn denied_as(sql: &str, want: &str) {
    match is_read_only(sql) {
        Err(GuardError::DeniedFunction(got)) => assert_eq!(got, want, "for `{sql}`"),
        other => panic!("expected DeniedFunction({want}) for `{sql}`, got {other:?}"),
    }
}

#[test]
fn denied_function_in_attribute_notation_rejected() {
    for (sql, want) in [
        (
            "SELECT (pid).pg_terminate_backend FROM pg_locks",
            "pg_terminate_backend",
        ),
        ("SELECT ('select 1'::text).ts_stat", "ts_stat"),
        ("SELECT (1).lo_creat", "lo_*"),
        ("SELECT (42).pg_advisory_lock", "pg_advisory_*"),
        ("SELECT (a).b.pg_cancel_backend FROM t", "pg_cancel_backend"),
        ("SELECT (a)[1].lo_unlink FROM t", "lo_*"),
        (
            r#"SELECT ("pid")."pg_terminate_backend" FROM t"#,
            "pg_terminate_backend",
        ),
        (
            "SELECT (pid).PG_TERMINATE_BACKEND FROM t",
            "pg_terminate_backend",
        ),
        (
            "SELECT 1 FROM t WHERE (pid).pg_cancel_backend",
            "pg_cancel_backend",
        ),
        ("SELECT ('http://x'::text).http_get", "http_get"),
        ("SELECT ((1).lo_creat)", "lo_*"),
        ("SELECT (r).invoke FROM r", "invoke"),
        ("SELECT (t.v).pg_notify FROM t", "pg_notify"),
    ] {
        denied_as(sql, want);
    }
}

/// `row.f` passes the whole row: a subquery shaped like the argument's
/// composite type is enough to call a one-argument function. Exact names
/// are refused here only when the function takes one row (`http`); a family
/// is refused whatever it takes, since it also stands for names not listed.
#[test]
fn denied_function_as_qualified_column_rejected() {
    for (sql, want) in [
        (
            "SELECT r.http FROM (SELECT 'GET', 'http://x', NULL, NULL, NULL) r",
            "http",
        ),
        ("SELECT t.HTTP FROM t", "http"),
        (
            "SELECT 1 FROM t ORDER BY t.pg_advisory_lock",
            "pg_advisory_*",
        ),
        ("SELECT t.pgr_dijkstra FROM t", "pgr_*"),
    ] {
        denied_as(sql, want);
    }
}

/// Three or more parts: `t.col.f` is `f(t.col)` — a call with the
/// column's value, which any one-argument function accepts.
#[test]
fn denied_function_after_a_column_rejected() {
    for (sql, want) in [
        ("SELECT s.t.set_config FROM s.t", "set_config"),
        ("SELECT t.x.pg_ls_dir FROM t", "pg_ls_dir"),
        ("SELECT t.url.http_get FROM t", "http_get"),
        ("SELECT t.fn.invoke FROM t", "invoke"),
    ] {
        denied_as(sql, want);
    }
}

/// `alias.name` can only call `name` with the alias's whole row; an exact
/// entry no single row can be passed to is an ordinary column there.
#[test]
fn qualified_column_named_like_a_multi_argument_function_allowed() {
    ok("SELECT r.invoke, t.pg_notify, t.set_config FROM r JOIN t ON true");
    ok("SELECT t.pg_read_file, t.http_get, t.schedule FROM t");
    ok("SELECT 1 FROM t WHERE t.setseed > 0 ORDER BY t.ts_stat");
}

#[test]
fn attribute_notation_checked_in_write_mode() {
    for sql in [
        "UPDATE t SET a = (1).lo_creat",
        "INSERT INTO t SELECT (pid).pg_terminate_backend FROM s",
        "DELETE FROM t WHERE (pid).pg_terminate_backend RETURNING t.id",
    ] {
        assert!(
            matches!(
                check_sql(sql, Access::ReadWrite),
                Err(GuardError::DeniedFunction(_))
            ),
            "for `{sql}`"
        );
    }
}

#[test]
fn ordinary_field_access_still_allowed() {
    ok("SELECT t.id, t.http_status, s.t.name FROM s.t");
    ok("SELECT (t).id, (t.addr).city, (a).b.c FROM t");
    ok("SELECT a[1], a[1].b, m['k'] FROM t");
    ok("SELECT lo_price, http, invoke FROM t");
    ok("SELECT (pid).pg_backend_pid FROM t");
}

/// The price of matching a family by prefix: a qualified column whose name
/// starts like one is refused. Unqualified, it is only ever a column.
#[test]
fn qualified_column_named_like_a_denied_family_is_refused() {
    denied_as("SELECT l.lo_revenue FROM lineorder l", "lo_*");
    ok("SELECT lo_revenue FROM lineorder");
}
