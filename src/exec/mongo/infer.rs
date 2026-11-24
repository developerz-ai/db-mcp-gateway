//! Field inference for `describe_schema` `detail: full` on Mongo: the field
//! paths and value types seen in a bounded sample of a collection's
//! documents. A collection has no declared schema, so this is the closest
//! answer — `count` says how many sampled documents held the field, so a
//! sparse field reads as sparse.
//!
//! Only names and type names leave here, never a value.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

/// Nesting followed into sub-documents (`a.b.c`); deeper fields are
/// reported at this depth as `object`.
const MAX_DEPTH: usize = 3;
/// Distinct field paths reported per collection, in name order.
const MAX_FIELDS: usize = 200;

/// `{sampled, fields: [{name, types, count}], truncated}` over `documents`.
pub(super) fn infer_fields(documents: &[Value]) -> Value {
    let mut fields: BTreeMap<String, Seen> = BTreeMap::new();
    for document in documents {
        if let Value::Object(map) = document {
            walk(map, "", 1, &mut fields);
        }
    }
    let truncated = fields.len() > MAX_FIELDS;
    let fields: Vec<Value> = fields
        .into_iter()
        .take(MAX_FIELDS)
        .map(|(name, seen)| json!({ "name": name, "types": seen.types, "count": seen.count }))
        .collect();
    json!({ "sampled": documents.len(), "fields": fields, "truncated": truncated })
}

#[derive(Default)]
struct Seen {
    /// Distinct type names, in first-seen order.
    types: Vec<&'static str>,
    count: usize,
}

fn walk(map: &Map<String, Value>, prefix: &str, depth: usize, fields: &mut BTreeMap<String, Seen>) {
    for (key, value) in map {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let kind = type_name(value);
        let seen = fields.entry(path.clone()).or_default();
        seen.count += 1;
        if !seen.types.contains(&kind) {
            seen.types.push(kind);
        }
        if let (Value::Object(child), "object") = (value, kind)
            && depth < MAX_DEPTH
        {
            walk(child, &path, depth + 1, fields);
        }
    }
}

/// The BSON type behind a relaxed extended JSON value (`{"$oid": …}` is an
/// `objectId`), else the JSON type.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "double",
        Value::Number(_) => "int",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(map) => extended_json_type(map).unwrap_or("object"),
    }
}

/// The BSON type a one-key object is the extended JSON of, when its value
/// has that wrapper's shape. A stored subdocument may itself use a `$` key
/// (`{"$oid": {"x": 1}}`); one whose value does not fit is walked as the
/// object it is.
fn extended_json_type(map: &Map<String, Value>) -> Option<&'static str> {
    let mut entries = map.iter();
    let (Some((key, value)), None) = (entries.next(), entries.next()) else {
        return None;
    };
    let is_string = value.is_string();
    let has = |fields: &[&str]| {
        value
            .as_object()
            .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f)))
    };
    let (kind, fits) = match key.as_str() {
        "$oid" => (
            "objectId",
            value
                .as_str()
                .is_some_and(|hex| hex.len() == 24 && hex.bytes().all(|b| b.is_ascii_hexdigit())),
        ),
        "$date" => ("date", is_string || has(&["$numberLong"])),
        "$numberDecimal" => ("decimal", is_string),
        "$numberLong" => ("long", is_string),
        "$numberDouble" => ("double", is_string),
        "$binary" => ("binary", has(&["base64", "subType"])),
        "$uuid" => ("binary", is_string),
        "$timestamp" => ("timestamp", has(&["t", "i"])),
        "$regularExpression" => ("regex", has(&["pattern", "options"])),
        "$minKey" => ("minKey", value == &Value::from(1)),
        "$maxKey" => ("maxKey", value == &Value::from(1)),
        _ => return None,
    };
    fits.then_some(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_types_and_counts_never_values() {
        let documents = vec![
            json!({ "_id": { "$oid": "65f0c0ffee0000000000abcd" }, "email": "alice@example.com",
                    "address": { "city": "Oslo", "geo": { "lat": 1.5 } }, "tags": ["a"] }),
            json!({ "_id": { "$oid": "65f0c0ffef0000000000abcd" }, "email": null, "age": 41,
                    "created": { "$date": "2024-01-01T00:00:00Z" } }),
        ];
        let inferred = infer_fields(&documents);
        assert_eq!(inferred["sampled"], 2);
        let field = |name: &str| {
            inferred["fields"]
                .as_array()
                .and_then(|fields| fields.iter().find(|f| f["name"] == name))
                .cloned()
                .unwrap_or(Value::Null)
        };
        assert_eq!(field("_id")["types"], json!(["objectId"]));
        assert_eq!(field("_id")["count"], 2);
        assert_eq!(field("email")["types"], json!(["string", "null"]));
        assert_eq!(
            field("age"),
            json!({ "name": "age", "types": ["int"], "count": 1 })
        );
        assert_eq!(field("address.geo.lat")["types"], json!(["double"]));
        assert_eq!(field("created")["types"], json!(["date"]));
        assert_eq!(field("tags")["types"], json!(["array"]));
        let rendered = inferred.to_string();
        for value in ["alice@example.com", "Oslo", "65f0c0ffee", "2024-01-01"] {
            assert!(!rendered.contains(value), "{value} leaked: {rendered}");
        }
    }

    /// A stored subdocument whose one key is `$oid` but whose value is not
    /// an ObjectId's is an object, and its child field is walked.
    #[test]
    fn a_dollar_key_subdocument_is_not_taken_for_a_wrapper() {
        let documents = vec![json!({ "ref": { "$oid": { "inner": 1 } },
                                     "when": { "$date": { "$numberLong": "1" } } })];
        let inferred = infer_fields(&documents);
        let types = |name: &str| {
            inferred["fields"]
                .as_array()
                .and_then(|fields| fields.iter().find(|f| f["name"] == name))
                .map(|f| f["types"].clone())
                .unwrap_or(Value::Null)
        };
        assert_eq!(types("ref"), json!(["object"]));
        assert_eq!(types("ref.$oid"), json!(["object"]));
        assert_eq!(types("ref.$oid.inner"), json!(["int"]));
        assert_eq!(types("when"), json!(["date"]));
    }

    #[test]
    fn nesting_and_field_count_are_bounded() {
        let deep = json!({ "a": { "b": { "c": { "d": 1 } } } });
        let inferred = infer_fields(&[deep]);
        let names: Vec<&str> = inferred["fields"]
            .as_array()
            .map(|f| f.iter().filter_map(|f| f["name"].as_str()).collect())
            .unwrap_or_default();
        assert_eq!(names, vec!["a", "a.b", "a.b.c"]);

        let wide: Map<String, Value> = (0..MAX_FIELDS + 5)
            .map(|i| (format!("f{i:04}"), json!(1)))
            .collect();
        let inferred = infer_fields(&[Value::Object(wide)]);
        assert_eq!(
            inferred["fields"].as_array().map(Vec::len),
            Some(MAX_FIELDS)
        );
        assert_eq!(inferred["truncated"], true);
    }
}
