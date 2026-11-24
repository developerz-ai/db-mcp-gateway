use super::*;

// --- Session-state, other-backend, dynamic-SQL and large-object families ---
//
// Each family is checked in the three positions a call can hide in: the
// projection, a FROM-clause table function, and a CTE body.

/// `(call, reported name)` — one representative per denied family.
const FAMILIES: &[(&str, &str)] = &[
    ("set_config('search_path', 'x', false)", "set_config"),
    ("pg_advisory_lock(1)", "pg_advisory_*"),
    ("pg_advisory_xact_lock_shared(1)", "pg_advisory_*"),
    ("pg_try_advisory_lock(1)", "pg_try_advisory_*"),
    ("pg_cancel_backend(1)", "pg_cancel_backend"),
    ("pg_terminate_backend(1)", "pg_terminate_backend"),
    ("query_to_xml('select 1', true, true, '')", "query_to_xml*"),
    (
        "query_to_xml_and_xmlschema('select 1', true, true, '')",
        "query_to_xml*",
    ),
    ("cursor_to_xml('c', 1, true, true, '')", "cursor_to_xml*"),
    ("table_to_xml('t', true, true, '')", "table_to_xml*"),
    ("schema_to_xml('public', true, true, '')", "schema_to_xml*"),
    ("database_to_xml(true, true, '')", "database_to_xml*"),
    ("dblink('host=x', 'select 1')", "dblink*"),
    ("dblink_exec('host=x', 'delete from t')", "dblink*"),
    ("pg_ls_waldir()", "pg_ls_*"),
    ("pg_ls_logdir()", "pg_ls_*"),
    ("pg_current_logfile()", "pg_current_logfile"),
    ("lo_from_bytea(0, 'x')", "lo_*"),
    ("lo_unlink(1)", "lo_*"),
    ("lowrite(1, 'x')", "lowrite"),
    ("pg_notify('jobs', '{\"run\":\"x\"}')", "pg_notify"),
    (
        "pg_logical_emit_message(true, 'p', 'm')",
        "pg_logical_emit_message",
    ),
    ("ts_stat('UPDATE t SET a = 1 RETURNING v')", "ts_stat"),
    (
        "ts_rewrite('a'::tsquery, 'SELECT q, r FROM t')",
        "ts_rewrite",
    ),
    ("crosstab('select 1, 2, 3')", "crosstab*"),
    ("crosstab4('select 1, 2, 3')", "crosstab*"),
    ("connectby('t', 'k', 'p', '1', 0)", "connectby"),
    ("xpath_table('k', 'doc', 't', '/a', 'true')", "xpath_table"),
    (
        "aws_s3.query_export_to_s3('select 1', 's3uri')",
        "query_export_to_s3",
    ),
    (
        "aws_s3.table_import_from_s3('t', '', '', 's3uri')",
        "table_import_from_s3",
    ),
    ("aws_lambda.invoke('fn', '{}'::json)", "invoke"),
    ("http(('GET', 'http://x', NULL, NULL, NULL))", "http"),
    ("http_get('http://169.254.169.254/')", "http_get"),
    ("net.http_post('http://x', '{}'::jsonb)", "http_post"),
    ("http_set_curlopt('CURLOPT_PROXY', 'x')", "http_set_curlopt"),
    (
        "pg_logical_slot_get_changes('s', NULL, NULL)",
        "pg_logical_slot_*",
    ),
    (
        "pg_logical_slot_peek_binary_changes('s', NULL, NULL)",
        "pg_logical_slot_*",
    ),
    (
        "pg_replication_slot_advance('s', '0/1')",
        "pg_replication_slot_advance",
    ),
    ("pg_drop_replication_slot('s')", "pg_drop_replication_slot"),
    (
        "pg_create_logical_replication_slot('s', 'pgoutput')",
        "pg_create_*",
    ),
    ("pg_create_physical_replication_slot('s')", "pg_create_*"),
    ("pg_copy_logical_replication_slot('s', 'd')", "pg_copy_*"),
    (
        "pg_replication_origin_advance('o', '0/1')",
        "pg_replication_origin_*",
    ),
    ("pg_stat_reset()", "pg_stat_reset*"),
    ("pg_stat_reset_shared('bgwriter')", "pg_stat_reset*"),
    ("pg_stat_statements_reset()", "pg_stat_statements_reset"),
    ("setseed(0.5)", "setseed"),
    ("pg_stat_get_activity(NULL)", "pg_stat_get_activity"),
    ("pg_stat_get_backend_activity(1)", "pg_stat_get_backend_*"),
    ("pg_prepared_statement()", "pg_prepared_statement"),
];

fn denied_as(sql: &str, want: &str) {
    match is_read_only(sql) {
        Err(GuardError::DeniedFunction(got)) => assert_eq!(got, want, "for `{sql}`"),
        other => panic!("expected DeniedFunction({want}) for `{sql}`, got {other:?}"),
    }
}

#[test]
fn every_family_rejected_in_projection() {
    for (call, want) in FAMILIES {
        denied_as(&format!("SELECT {call}"), want);
    }
}

#[test]
fn every_family_rejected_as_table_function() {
    for (call, want) in FAMILIES {
        denied_as(&format!("SELECT * FROM {call} AS f"), want);
    }
}

#[test]
fn every_family_rejected_in_cte() {
    for (call, want) in FAMILIES {
        denied_as(
            &format!("WITH c AS (SELECT {call} AS v) SELECT v FROM c"),
            want,
        );
    }
}

#[test]
fn families_rejected_in_write_mode_too() {
    for (call, want) in FAMILIES {
        let sql = format!("UPDATE t SET a = 1 WHERE b = {call}");
        match check_sql(&sql, Access::ReadWrite) {
            Err(GuardError::DeniedFunction(got)) => assert_eq!(got, *want, "for `{sql}`"),
            other => panic!("expected DeniedFunction({want}) for `{sql}`, got {other:?}"),
        }
    }
}

#[test]
fn case_and_schema_qualification_do_not_bypass() {
    denied_as(
        "SELECT PG_CATALOG.Set_Config('a', 'b', false)",
        "set_config",
    );
    denied_as("SELECT public.DBLINK('x', 'y')", "dblink*");
    denied_as("SELECT PG_CATALOG.PG_NOTIFY('c', 'p')", "pg_notify");
}

/// A prefix family must not swallow ordinary relations or near-miss names:
/// a table is not a call, and `lower` / `lo` are not `lo_*`.
#[test]
fn prefixes_do_not_match_relations_or_near_misses() {
    ok("SELECT * FROM lo_items");
    ok("SELECT * FROM dblink_audit d JOIN table_to_xml_cache c ON d.id = c.id");
    ok("SELECT lower('A'), lo FROM t");
    ok("SELECT pg_advisory FROM t");
    // `ts_stat` / `ts_rewrite` are exact: other text-search functions read.
    ok("SELECT to_tsvector('a b'), ts_rank(v, q), ts_headline('x', q) FROM t");
    ok("SELECT * FROM ts_stats");
}

/// `DESCRIBE t` parses as `ExplainTable`; it is not Postgres and is denied.
#[test]
fn explain_table_rejected() {
    rejected_not_allowed("DESCRIBE t", "EXPLAIN TABLE");
}
