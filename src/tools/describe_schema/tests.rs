use super::*;

/// Confirms `assemble_tables` correctly groups consecutive rows by
/// (schema, table_name) and decodes is_nullable from the YES/NO text
/// that information_schema returns.
#[test]
fn assemble_groups_by_table_and_decodes_nullable() {
    let rows = vec![
        vec![
            Value::from("public"),
            Value::from("users"),
            Value::from("id"),
            Value::from("bigint"),
            Value::from("NO"),
        ],
        vec![
            Value::from("public"),
            Value::from("users"),
            Value::from("email"),
            Value::from("text"),
            Value::from("YES"),
        ],
        vec![
            Value::from("public"),
            Value::from("orders"),
            Value::from("id"),
            Value::from("bigint"),
            Value::from("NO"),
        ],
    ];
    let exec_result = ExecResult {
        columns: vec![
            "table_schema".into(),
            "table_name".into(),
            "column_name".into(),
            "data_type".into(),
            "is_nullable".into(),
        ],
        rows,
        truncated: false,
        elapsed_ms: 0,
        rows_affected: None,
    };
    let assembled = assemble_tables(&exec_result).unwrap();
    assert_eq!(assembled.tables.len(), 2);
    assert_eq!(assembled.tables[0].name, "users");
    assert_eq!(assembled.tables[0].columns.len(), 2);
    assert!(!assembled.tables[0].columns[0].nullable);
    assert!(assembled.tables[0].columns[1].nullable);
    assert_eq!(assembled.tables[1].name, "orders");
    assert_eq!(assembled.tables[1].columns.len(), 1);
    assert!(!assembled.truncated);

    // Capped scan: the table the cut fell in may be partial, so it goes.
    let capped = ExecResult {
        truncated: true,
        ..exec_result
    };
    let assembled = assemble_tables(&capped).unwrap();
    assert!(assembled.truncated);
    assert_eq!(assembled.tables.len(), 1);
    assert_eq!(assembled.tables[0].name, "users");
}
