//! Unit tests for `sample_table`'s argument parsing.

use super::*;

#[test]
fn parse_table_defaults_schema_and_names_the_bad_argument() {
    let table = parse_table(None, None, "users").expect("valid");
    assert_eq!(table.schema.as_str(), DEFAULT_SCHEMA);
    assert_eq!(table.table.as_str(), "users");
    assert_eq!(
        parse_table(None, Some("bad-schema"), "users").err(),
        Some(("schema", IDENTIFIER_PATTERN))
    );
    assert_eq!(
        parse_table(Some("postgres"), None, "users; drop").err(),
        Some(("table", IDENTIFIER_PATTERN))
    );
}

/// A Mongo collection may hold `-` and `.`; a bad one names the collection
/// rule, not the SQL identifier one.
#[test]
fn a_mongo_table_is_a_collection_name() {
    let table = parse_table(Some("mongo"), None, "order-items.v2").expect("valid");
    assert_eq!(table.table.as_str(), "order-items.v2");
    assert_eq!(
        parse_table(Some("postgres"), None, "order-items").err(),
        Some(("table", IDENTIFIER_PATTERN))
    );
    for bad in ["events.", "users; drop", "-x"] {
        assert_eq!(
            parse_table(Some("mongo"), None, bad).err(),
            Some(("table", COLLECTION_PATTERN)),
            "{bad}"
        );
    }
}

#[test]
fn audited_read_names_the_table_or_the_mongo_find() {
    let table = parse_table(None, Some("sales"), "orders").expect("valid");
    assert_eq!(audited_read(Some("postgres"), table), "sales.orders");
    let find: Value = serde_json::from_str(&audited_read(Some("mongo"), table))
        .expect("the Mongo read is a JSON command");
    assert_eq!(find, serde_json::json!({ "find": "orders", "filter": {} }));
}
