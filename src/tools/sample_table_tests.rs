//! Unit tests for `sample_table`'s argument parsing.

use super::*;

#[test]
fn parse_table_defaults_schema_and_names_the_bad_argument() {
    let table = parse_table(None, "users").expect("valid");
    assert_eq!(table.schema.as_str(), DEFAULT_SCHEMA);
    assert_eq!(table.table.as_str(), "users");
    assert_eq!(
        parse_table(Some("bad-schema"), "users").err(),
        Some(("schema", IDENTIFIER_PATTERN))
    );
}

/// Before authz the kind is not consulted: `table` is held to the loosest
/// rule, a collection name, whatever server it names.
#[test]
fn before_authz_a_table_is_held_to_the_collection_rule() {
    let table = parse_table(None, "order-items.v2").expect("valid");
    assert_eq!(table.table.as_str(), "order-items.v2");
    for bad in ["events.", "users; drop", "-x", "a b"] {
        assert_eq!(
            parse_table(None, bad).err(),
            Some(("table", COLLECTION_PATTERN)),
            "{bad}"
        );
    }
}

/// After authz the target's rule applies: a SQL table is an identifier, a
/// Mongo `system.*` collection is refused `forbidden`.
#[test]
fn after_authz_the_target_kind_decides() {
    let table = |name| parse_table(None, name).expect("valid").table;
    let refused = |kind, name| refuse_for_kind(Value::Null, kind, table(name)).map(|o| o.code);
    assert_eq!(refused(ServerKind::Mongo, "order-items.v2"), None);
    assert_eq!(refused(ServerKind::Postgres, "users"), None);
    assert_eq!(
        refused(ServerKind::Postgres, "order-items"),
        Some(OutcomeCode::InvalidArguments)
    );
    assert_eq!(
        refused(ServerKind::Mysql, "a.b"),
        Some(OutcomeCode::InvalidArguments)
    );
    assert_eq!(
        refused(ServerKind::Mongo, "system.profile"),
        Some(OutcomeCode::Forbidden)
    );
}

#[test]
fn audited_read_names_the_table_or_the_mongo_find() {
    let table = parse_table(Some("sales"), "orders").expect("valid");
    assert_eq!(audited_read(Some("postgres"), table), "sales.orders");
    let find: Value = serde_json::from_str(&audited_read(Some("mongo"), table))
        .expect("the Mongo read is a JSON command");
    assert_eq!(find, serde_json::json!({ "find": "orders", "filter": {} }));
}

/// `columns` keeps the caller's order and refuses a repeat, however long
/// the list.
#[test]
fn parse_columns_keeps_order_and_refuses_a_repeat() {
    let named: Vec<String> = (0..50_000).rev().map(|i| format!("c{i}")).collect();
    let parsed = parse_columns(Some(&named)).expect("all unique");
    assert_eq!(parsed.first(), Some(&"c49999"));
    assert_eq!(parsed.last(), Some(&"c0"));
    let repeated = ["b", "a", "b"].map(String::from);
    assert_eq!(
        parse_columns(Some(&repeated)),
        Err("`columns` names `b` twice".to_owned())
    );
}
