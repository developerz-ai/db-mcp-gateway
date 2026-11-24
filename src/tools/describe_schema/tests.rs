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
        column_types: Vec::new(),
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
    let tables = assemble_tables(&exec_result).unwrap();
    assert_eq!(tables.len(), 2);
    assert_eq!(tables[0].name, "users");
    assert_eq!(tables[0].columns.len(), 2);
    assert!(!tables[0].columns[0].nullable);
    assert!(tables[0].columns[1].nullable);
    assert_eq!(tables[1].name, "orders");
    assert_eq!(tables[1].columns.len(), 1);

    // The default shape is exactly what the tool always answered.
    let (count, text) = render(Detail::Columns, &exec_result, None).unwrap();
    assert_eq!(count, 2);
    let rendered: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        rendered["tables"][0],
        serde_json::json!({ "schema": "public", "name": "users", "columns": [
            { "name": "id", "data_type": "bigint", "nullable": false },
            { "name": "email", "data_type": "text", "nullable": true },
        ]})
    );
    assert_eq!(rendered["truncated"], false);
    assert!(rendered.get("schemas").is_none(), "{rendered}");

    // Capped scan: the table the cut fell in may be partial, so it goes.
    let capped = ExecResult {
        truncated: true,
        ..exec_result
    };
    let tables = assemble_tables(&capped).unwrap();
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].name, "users");
}

#[test]
fn names_and_full_rows_render_one_table_each() {
    let result = |rows: Vec<Vec<Value>>| ExecResult {
        columns: Vec::new(),
        column_types: Vec::new(),
        rows,
        truncated: false,
        elapsed_ms: 0,
        rows_affected: None,
    };
    let names = result(vec![vec!["public".into(), "users".into(), "table".into()]]);
    let (count, text) = render(Detail::Names, &names, Some(vec!["public".into()])).unwrap();
    assert_eq!(count, 1);
    let rendered: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(rendered["tables"][0]["kind"], "table");
    assert_eq!(rendered["schemas"], serde_json::json!(["public"]));

    let full = result(vec![vec![
        "public".into(),
        "users".into(),
        "table".into(),
        Value::Null,
        Value::from(42),
        serde_json::json!([{ "name": "id", "data_type": "bigint", "nullable": false }]),
        serde_json::json!(["id"]),
        serde_json::json!([]),
        serde_json::json!([]),
    ]]);
    let (_, text) = render(Detail::Full, &full, None).unwrap();
    let rendered: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(rendered["tables"][0]["row_estimate"], 42);
    assert_eq!(
        rendered["tables"][0]["primary_key"],
        serde_json::json!(["id"])
    );
    assert!(rendered["tables"][0].get("comment").is_none());

    assert!(render(Detail::Full, &names, None).is_err());
    assert!(render(Detail::Names, &full, None).is_err());
}
