//! `extract_plan` over the cell shapes the adapter may answer with.

use super::*;

#[test]
fn extract_plan_decodes_string_cell() {
    let result = crate::exec::ExecResult {
        columns: vec!["QUERY PLAN".to_string()],
        column_types: Vec::new(),
        rows: vec![vec![Value::from(r#"[{"Plan":{"Node Type":"Seq Scan"}}]"#)]],
        truncated: false,
        elapsed_ms: 0,
        rows_affected: None,
    };
    let plan = extract_plan(&result).expect("decodes");
    assert_eq!(plan[0]["Plan"]["Node Type"], "Seq Scan");
}

#[test]
fn extract_plan_passes_through_already_parsed_json() {
    // When sqlx decodes a `json` column directly, the cell is already a
    // Value::Array (or Object) — pass through without re-parsing.
    let result = crate::exec::ExecResult {
        columns: vec!["QUERY PLAN".to_string()],
        column_types: Vec::new(),
        rows: vec![vec![serde_json::json!([{"Plan": {"Node Type": "Result"}}])]],
        truncated: false,
        elapsed_ms: 0,
        rows_affected: None,
    };
    let plan = extract_plan(&result).expect("passes through");
    assert_eq!(plan[0]["Plan"]["Node Type"], "Result");
}

#[test]
fn extract_plan_errors_on_empty_or_unexpected_shape() {
    let empty = crate::exec::ExecResult {
        columns: vec![],
        column_types: Vec::new(),
        rows: vec![],
        truncated: false,
        elapsed_ms: 0,
        rows_affected: None,
    };
    assert!(extract_plan(&empty).is_err());

    // Wrong cell type (number)
    let wrong = crate::exec::ExecResult {
        columns: vec!["QUERY PLAN".to_string()],
        column_types: Vec::new(),
        rows: vec![vec![Value::from(42)]],
        truncated: false,
        elapsed_ms: 0,
        rows_affected: None,
    };
    assert!(extract_plan(&wrong).is_err());
}
