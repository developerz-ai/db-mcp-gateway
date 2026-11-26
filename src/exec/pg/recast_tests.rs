//! The wrapper text and the terminator cut.

use super::*;
use sqlx::TypeInfo;

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
fn bound_types_preserve_placeholder_order_and_null_inference() {
    let params = [
        QueryParam::Null,
        QueryParam::Bool(true),
        QueryParam::Int(1),
        QueryParam::Float(0.5),
        QueryParam::Text("x".into()),
        QueryParam::Json(serde_json::json!({"a": 1})),
    ];
    let types = bound_types(&["bound"], &params);
    let names: Vec<&str> = types.iter().map(TypeInfo::name).collect();
    assert_eq!(
        names,
        ["TEXT", "?", "BOOL", "INT8", "FLOAT8", "TEXT", "JSONB"]
    );
}
