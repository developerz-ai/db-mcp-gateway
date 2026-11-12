use super::*;

// --- Function denylist ---

fn rejected_denied(sql: &str, fn_name: &str) {
    match is_read_only(sql) {
        Err(GuardError::DeniedFunction(got)) => {
            assert_eq!(got, fn_name, "wrong denied function for `{sql}`");
        }
        other => panic!("expected DeniedFunction({fn_name}) for `{sql}`, got {other:?}"),
    }
}

#[test]
fn pg_read_file_in_projection_rejected() {
    rejected_denied("SELECT pg_read_file('/etc/passwd')", "pg_read_file");
}

#[test]
fn pg_read_binary_file_rejected() {
    rejected_denied(
        "SELECT pg_read_binary_file('/etc/shadow')",
        "pg_read_binary_file",
    );
}

#[test]
fn pg_ls_dir_rejected() {
    rejected_denied("SELECT * FROM pg_ls_dir('/tmp')", "pg_ls_dir");
    // `LATERAL` puts the same call in a different table-factor variant.
    rejected_denied("SELECT * FROM t, LATERAL pg_ls_dir('/tmp')", "pg_ls_dir");
}

#[test]
fn pg_stat_file_rejected() {
    rejected_denied("SELECT pg_stat_file('/etc/passwd')", "pg_stat_file");
}

#[test]
fn lo_export_rejected() {
    rejected_denied("SELECT lo_export(1234, '/tmp/out')", "lo_export");
}

#[test]
fn lo_import_rejected() {
    rejected_denied("SELECT lo_import('/etc/passwd')", "lo_import");
}

#[test]
fn denied_function_in_where_clause_rejected() {
    rejected_denied(
        "SELECT id FROM t WHERE pg_read_file('/etc/passwd') IS NOT NULL",
        "pg_read_file",
    );
}

#[test]
fn denied_function_in_subquery_rejected() {
    rejected_denied(
        "SELECT id FROM t WHERE id IN (SELECT length(pg_read_file('/etc/passwd')))",
        "pg_read_file",
    );
}

#[test]
fn denied_function_in_cte_rejected() {
    rejected_denied(
        "WITH x AS (SELECT pg_read_file('/etc/passwd') AS data) SELECT data FROM x",
        "pg_read_file",
    );
}

#[test]
fn schema_qualified_denied_function_rejected() {
    // Attackers may try to qualify the name to confuse a naive denylist.
    rejected_denied(
        "SELECT pg_catalog.pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
}

#[test]
fn denied_function_case_insensitive() {
    // SQL identifiers are case-insensitive; the guard must be too.
    rejected_denied("SELECT PG_READ_FILE('/etc/passwd')", "pg_read_file");
}

#[test]
fn denied_function_in_having_rejected() {
    rejected_denied(
        "SELECT id FROM t GROUP BY id HAVING pg_read_file('/etc/passwd') IS NOT NULL",
        "pg_read_file",
    );
}

#[test]
fn denied_function_in_query_tail_rejected() {
    // ORDER BY / LIMIT / OFFSET hang off `Query`, not off the SELECT body —
    // the Visit derive reaches them via the same walk as the projection.
    rejected_denied(
        "SELECT id FROM t ORDER BY pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT id FROM t LIMIT length(pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT id FROM t OFFSET length(pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
    // Same tail on an inner query, reached through the CTE walk.
    rejected_denied(
        "WITH x AS (SELECT id FROM t ORDER BY pg_read_file('/etc/passwd')) SELECT * FROM x",
        "pg_read_file",
    );
}

#[test]
fn denied_function_in_join_constraint_rejected() {
    // A join's ON predicate is an expression position like any other.
    rejected_denied(
        "SELECT a.id FROM a JOIN b ON pg_read_file('/etc/passwd') IS NOT NULL",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT a.id FROM a LEFT JOIN b ON a.id = length(pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
    // Parenthesised join tree — a `NestedJoin` table factor.
    rejected_denied(
        "SELECT * FROM (a JOIN b ON pg_read_file('/etc/passwd') IS NOT NULL)",
        "pg_read_file",
    );
}

#[test]
fn safe_functions_allowed() {
    // Ensure the denylist doesn't block ordinary aggregate/window functions.
    ok("SELECT now()");
    ok("SELECT count(*) FROM users");
    ok("SELECT sum(amount) FROM orders GROUP BY user_id");
    ok("SELECT lower(email) FROM users");
    ok("SELECT coalesce(name, 'unknown') FROM t");
}

// --- Escape-position regressions (issue #138) ---
//
// Each of these was empirically shown to reach the target DB with the old
// hand-rolled `check_expr` — its `_ => Ok(())` fallthrough silently allowed
// every `Expr` variant the author hadn't listed. The visitor-based walk
// covers them without enumeration; these tests pin that guarantee.

#[test]
fn denied_in_exists_subquery_rejected() {
    rejected_denied(
        "SELECT 1 WHERE EXISTS (SELECT pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
}

#[test]
fn denied_in_any_all_subquery_rejected() {
    rejected_denied(
        "SELECT a FROM t WHERE a = ANY(SELECT pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT a FROM t WHERE a = ALL(SELECT pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
}

#[test]
fn denied_in_tuple_rejected() {
    rejected_denied("SELECT (pg_read_file('/etc/passwd'), 1)", "pg_read_file");
}

#[test]
fn denied_in_array_literal_rejected() {
    rejected_denied("SELECT ARRAY[pg_read_file('/etc/passwd')]", "pg_read_file");
}

#[test]
fn denied_in_filter_clause_rejected() {
    rejected_denied(
        "SELECT count(*) FILTER (WHERE pg_read_file('/etc/passwd') IS NOT NULL) FROM t",
        "pg_read_file",
    );
}

#[test]
fn denied_in_window_frame_rejected() {
    rejected_denied(
        "SELECT sum(a) OVER (ORDER BY pg_read_file('/etc/passwd')) FROM t",
        "pg_read_file",
    );
}

#[test]
fn denied_in_distinct_on_rejected() {
    rejected_denied(
        "SELECT DISTINCT ON (pg_read_file('/etc/passwd')) a FROM t",
        "pg_read_file",
    );
}

#[test]
fn denied_in_unnest_rejected() {
    rejected_denied(
        "SELECT * FROM UNNEST(ARRAY[pg_read_file('/etc/passwd')])",
        "pg_read_file",
    );
}

#[test]
fn denied_in_is_distinct_from_rejected() {
    rejected_denied(
        "SELECT a FROM t WHERE a IS DISTINCT FROM pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT a FROM t WHERE a IS NOT DISTINCT FROM pg_read_file('/etc/passwd')",
        "pg_read_file",
    );
}

#[test]
fn denied_in_substring_rejected() {
    // `substring(<expr> FROM ... FOR ...)` is `Expr::Substring`, not a
    // `Function` call — and the old walker fell through it.
    rejected_denied(
        "SELECT substring(pg_read_file('/etc/passwd') FROM 1 FOR 2)",
        "pg_read_file",
    );
}

#[test]
fn denied_in_grouping_sets_rejected() {
    rejected_denied(
        "SELECT a FROM t GROUP BY GROUPING SETS ((pg_read_file('/etc/passwd')))",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT a FROM t GROUP BY ROLLUP (pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
    rejected_denied(
        "SELECT a FROM t GROUP BY CUBE (pg_read_file('/etc/passwd'))",
        "pg_read_file",
    );
}
