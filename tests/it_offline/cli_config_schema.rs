//! website/static/config.schema.json against the serde types. The schema is
//! hand-written, so `tests/data/check/full.yaml` — every config key, once —
//! ties the two: it parses (every section denies unknown keys, so each key
//! exists in the serde types), and its key paths are exactly the schema's.

use std::collections::BTreeSet;

use db_mcp_gateway::config::ConfigFile;
use serde_json::Value;

const FULL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/check/full.yaml");
const SCHEMA: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/website/static/config.schema.json"
);

/// Maps keyed by operator-chosen names; the schema types their values with
/// `additionalProperties`, written `.*` here.
const NAME_MAPS: &[&str] = &[".constraint_profiles"];

fn yaml_paths(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let key = if NAME_MAPS.contains(&prefix) {
                    "*"
                } else {
                    key.as_str()
                };
                let path = format!("{prefix}.{key}");
                out.insert(path.clone());
                yaml_paths(child, &path, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                yaml_paths(item, &format!("{prefix}[]"), out);
            }
        }
        _ => {}
    }
}

fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    match node["$ref"].as_str() {
        Some(reference) => {
            let name = reference.strip_prefix("#/$defs/").expect("local $ref");
            &root["$defs"][name]
        }
        None => node,
    }
}

fn schema_paths(root: &Value, node: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    let node = resolve(root, node);
    if let Some(branches) = node["oneOf"].as_array() {
        for branch in branches {
            schema_paths(root, branch, prefix, out);
        }
    }
    if let Some(values @ Value::Object(_)) = node.get("additionalProperties") {
        out.insert(format!("{prefix}.*"));
        schema_paths(root, values, &format!("{prefix}.*"), out);
    }
    if let Some(items) = node.get("items") {
        schema_paths(root, items, &format!("{prefix}[]"), out);
    }
    if let Some(Value::Object(properties)) = node.get("properties") {
        assert_eq!(
            node["additionalProperties"],
            Value::Bool(false),
            "{prefix}: every object rejects unknown keys, as the serde types do"
        );
        for (key, child) in properties {
            let path = format!("{prefix}.{key}");
            out.insert(path.clone());
            schema_paths(root, child, &path, out);
        }
    }
}

#[test]
fn full_fixture_parses_with_the_real_parser() {
    ConfigFile::from_file(std::path::Path::new(FULL)).expect("full.yaml is a valid config");
}

#[test]
fn schema_keys_match_the_serde_types() {
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(SCHEMA).unwrap()).unwrap();
    let full: Value = serde_saphyr::from_str(&std::fs::read_to_string(FULL).unwrap()).unwrap();
    let mut from_schema = BTreeSet::new();
    schema_paths(&schema, &schema, "", &mut from_schema);
    let mut from_yaml = BTreeSet::new();
    yaml_paths(&full, "", &mut from_yaml);
    let only_schema: Vec<_> = from_schema.difference(&from_yaml).collect();
    let only_yaml: Vec<_> = from_yaml.difference(&from_schema).collect();
    assert!(
        only_schema.is_empty() && only_yaml.is_empty(),
        "schema-only keys (absent from full.yaml): {only_schema:?}\n\
         full.yaml-only keys (absent from the schema): {only_yaml:?}"
    );
}
