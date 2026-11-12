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
}

/// A prefix family must not swallow ordinary relations or near-miss names:
/// a table is not a call, and `lower` / `lo` are not `lo_*`.
#[test]
fn prefixes_do_not_match_relations_or_near_misses() {
    ok("SELECT * FROM lo_items");
    ok("SELECT * FROM dblink_audit d JOIN table_to_xml_cache c ON d.id = c.id");
    ok("SELECT lower('A'), lo FROM t");
    ok("SELECT pg_advisory FROM t");
}

/// `DESCRIBE t` parses as `ExplainTable`; it is not Postgres and is denied.
#[test]
fn explain_table_rejected() {
    rejected_not_allowed("DESCRIBE t", "EXPLAIN TABLE");
}
