//! The wrapper text, the terminator cut, the probe's types and when a read
//! is tried again.

use super::*;
use crate::exec::rejection::DbRejection;

#[test]
fn only_the_columns_without_binary_form_are_cast() {
    let wrapped = wrap(
        "SELECT oid, relacl, relname FROM pg_class",
        &[("oid", false), ("relacl", true), ("rel\"name", false)],
    );
    assert_eq!(
        wrapped,
        "SELECT q.c1 AS \"oid\", q.c2::text AS \"relacl\", q.c3 AS \"rel\"\"name\" FROM (\n\
         SELECT oid, relacl, relname FROM pg_class\n) AS q(c1, c2, c3)"
    );
}

/// A `;` is the terminator only as a token: one followed by a comment
/// still is, one inside a string or comment never is.
#[test]
fn the_body_ends_before_the_terminator_whatever_trails_it() {
    let body = |sql| statement_body(sql).expect("scans");
    assert_eq!(
        body("SELECT * FROM pg_class; -- c"),
        "SELECT * FROM pg_class"
    );
    assert_eq!(
        body("SELECT relacl FROM pg_class ; /* c */"),
        "SELECT relacl FROM pg_class"
    );
    assert_eq!(body("SELECT (1);\n ; "), "SELECT (1)");
    assert_eq!(body("SELECT ';' -- all;"), "SELECT ';'");
    assert_eq!(body("SELECT $1 /* ; */"), "SELECT $1");
    // Leading empty statements are cut too: the body nests.
    assert_eq!(
        body("; SELECT relacl FROM pg_class"),
        "SELECT relacl FROM pg_class"
    );
    assert_eq!(body(" ;; -- c\n ;(SELECT 1);"), "(SELECT 1)");
    assert_eq!(statement_body(" ; "), None);
}

#[test]
fn the_probe_is_prepared_with_the_params_types_and_run_on_nulls() {
    assert_eq!(param_types(&[]), "");
    let params = [
        QueryParam::Null,
        QueryParam::Bool(true),
        QueryParam::Int(1),
        QueryParam::Float(0.5),
        QueryParam::Text("x".into()),
        QueryParam::Json(serde_json::json!({"a": 1})),
    ];
    assert_eq!(
        param_types(&params),
        " (unknown, bool, int8, float8, text, jsonb)"
    );
    assert_eq!(execute_with_nulls("p", 0), "EXECUTE p");
    assert_eq!(execute_with_nulls("p", 2), "EXECUTE p(NULL, NULL)");
}

#[test]
fn only_a_read_refused_for_a_missing_function_is_tried_again() {
    let rejected = |code| ExecError::Rejected(DbRejection::new(code, "", ""));
    let mut query = ExecQuery {
        sql: "SELECT relacl FROM pg_class",
        binds: &[],
        statement_timeout_ms: None,
        row_limit: 1,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: uuid::Uuid::nil(),
    };
    assert!(may_apply(&rejected(NO_BINARY_OUTPUT), &query));
    assert!(!may_apply(&rejected("42601"), &query));
    assert!(may_apply(&ExecError::Sql, &query));
    assert!(!may_apply(&ExecError::Timeout, &query));
    query.access = Access::ReadWrite;
    assert!(!may_apply(&rejected(NO_BINARY_OUTPUT), &query));
}
