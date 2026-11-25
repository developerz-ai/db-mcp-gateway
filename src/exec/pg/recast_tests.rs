//! The wrapper text, the terminator cut and the types the nested statement
//! is proven with.

use super::super::stream::bound_types;
use super::*;
use sqlx::TypeInfo;
use sqlx::postgres::PgTypeInfo;

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

/// The proof is the unnamed `prepare_with` with the types the run binds. The
/// source is the guard: no named `PREPARE` to survive an abort and collide on
/// a pooled backend, and no param-type list drifting from `bound_types`.
#[test]
fn the_single_statement_proof_is_unnamed() {
    let source = include_str!("recast.rs");
    let at = source
        .find("async fn prove_single_statement")
        .expect("proof function");
    let proof = &source[at..];
    let proof = &proof[..proof.find("\n///").expect("end of proof function")];
    assert!(proof.contains(".prepare_with("), "{proof}");
    assert!(proof.contains("bound_types(binds, params)"), "{proof}");
    assert!(!proof.contains("PREPARE"), "{proof}");
    assert!(!proof.contains("DEALLOCATE"), "{proof}");
    assert!(!source.contains("dbmcp_recast"), "{source}");
    assert!(!source.contains("fn param_types"), "{source}");
}

#[test]
fn the_proof_uses_the_types_the_run_binds() {
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
    assert_eq!(types[0], PgTypeInfo::with_name("TEXT"), "a bind is text");
}
