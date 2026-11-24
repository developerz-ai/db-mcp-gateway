//! Field inference for `describe_schema` `detail: full` on Mongo: the field
//! paths and value types seen in a bounded sample of a collection's
//! documents. A collection has no declared schema, so this is the closest
//! answer — `count` says how many sampled documents held the field, so a
//! sparse field reads as sparse.
//!
//! The server names each field's type (`$type`) while the sample is read
//! (see [`field_types`]): the types are the stored BSON element types, so
//! a subdocument shaped like an ObjectId's extended JSON (`{"$oid": …}`) is
//! an `object`, never mistaken for the type it mimics (#385). No value
//! leaves the server, only names and type names.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Nesting followed into sub-documents (`a.b.c`); deeper fields are
/// reported at this depth as `object`.
const MAX_DEPTH: usize = 3;
/// Distinct field paths reported per collection, in name order.
const MAX_FIELDS: usize = 200;

/// The aggregation expression that turns a sampled document into its field
/// tree, `[{k: name, t: BSON type, c: [children]}]`, sub-documents followed
/// to [`MAX_DEPTH`]: a `$project` of it reads no value back. One field past
/// [`MAX_FIELDS`] per object: enough to report `truncated`, and a document
/// of very many fields does not outgrow the server's document limit.
pub(super) fn field_types() -> Value {
    level("$$ROOT", 1)
}

fn level(document: &str, depth: usize) -> Value {
    let field = format!("f{depth}");
    let value = format!("$${field}.v");
    let mut entry = json!({ "k": format!("$${field}.k"), "t": { "$type": value } });
    if depth < MAX_DEPTH {
        entry["c"] = json!({ "$cond": [
            { "$eq": [{ "$type": value }, "object"] },
            level(&value, depth + 1),
            { "$literal": [] },
        ] });
    }
    let fields = json!({ "$slice": [{ "$objectToArray": document }, MAX_FIELDS + 1] });
    json!({ "$map": { "input": fields, "as": field, "in": entry } })
}

/// `{sampled, fields: [{name, types, count}], truncated}` over the field
/// trees of the sampled documents (see [`field_types`]).
pub(super) fn infer_fields(documents: &[Value]) -> Value {
    let mut fields: BTreeMap<String, Seen> = BTreeMap::new();
    for document in documents {
        walk(document, "", &mut fields);
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
    types: Vec<String>,
    count: usize,
}

fn walk(tree: &Value, prefix: &str, fields: &mut BTreeMap<String, Seen>) {
    for entry in tree.as_array().into_iter().flatten() {
        let (Some(key), Some(kind)) = (entry["k"].as_str(), entry["t"].as_str()) else {
            continue;
        };
        let path = if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}.{key}")
        };
        let kind = type_name(kind);
        let seen = fields.entry(path.clone()).or_default();
        seen.count += 1;
        if !seen.types.iter().any(|known| known == kind) {
            seen.types.push(kind.to_string());
        }
        walk(&entry["c"], &path, fields);
    }
}

/// The server's BSON type name, but `binData` spelled `binary` as it was
/// before types came from the server.
fn type_name(bson_type: &str) -> &str {
    match bson_type {
        "binData" => "binary",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types(inferred: &Value, name: &str) -> Value {
        inferred["fields"]
            .as_array()
            .and_then(|fields| fields.iter().find(|f| f["name"] == name))
            .map(|f| f["types"].clone())
            .unwrap_or(Value::Null)
    }

    #[test]
    fn paths_types_and_counts_are_merged_over_the_documents() {
        let documents = vec![
            json!([
                { "k": "_id", "t": "objectId", "c": [] },
                { "k": "email", "t": "string", "c": [] },
                { "k": "blob", "t": "binData", "c": [] },
                { "k": "address", "t": "object", "c": [
                    { "k": "geo", "t": "object", "c": [{ "k": "lat", "t": "double" }] },
                ] },
            ]),
            json!([
                { "k": "_id", "t": "objectId", "c": [] },
                { "k": "email", "t": "null", "c": [] },
            ]),
        ];
        let inferred = infer_fields(&documents);
        assert_eq!(inferred["sampled"], 2);
        assert_eq!(
            inferred["fields"][0],
            json!({ "name": "_id", "types": ["objectId"], "count": 2 })
        );
        assert_eq!(types(&inferred, "email"), json!(["string", "null"]));
        assert_eq!(types(&inferred, "blob"), json!(["binary"]));
        assert_eq!(types(&inferred, "address"), json!(["object"]));
        assert_eq!(types(&inferred, "address.geo.lat"), json!(["double"]));
        assert_eq!(inferred["truncated"], false);
    }

    #[test]
    fn the_field_count_is_bounded() {
        let wide: Vec<Value> = (0..MAX_FIELDS + 1)
            .map(|i| json!({ "k": format!("f{i:04}"), "t": "int", "c": [] }))
            .collect();
        let inferred = infer_fields(&[Value::Array(wide)]);
        assert_eq!(
            inferred["fields"].as_array().map(Vec::len),
            Some(MAX_FIELDS)
        );
        assert_eq!(inferred["truncated"], true);
    }

    /// The expression is an ordinary read: the rejector takes it, and it
    /// nests exactly [`MAX_DEPTH`] levels.
    #[test]
    fn the_expression_passes_the_rejector_and_stops_at_the_depth_cap() {
        let expression = field_types();
        let command = json!({ "aggregate": "c", "pipeline": [
            { "$project": { "_id": 0, "fields": expression } },
        ], "cursor": {} });
        assert!(super::super::rejector::validate_command(&command.to_string()).is_ok());
        assert_eq!(
            expression.to_string().matches("$objectToArray").count(),
            MAX_DEPTH
        );
    }
}
