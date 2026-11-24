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
/// Fields read per level of one document: one past what is reported, enough
/// to know the sample was cut.
const LEVEL_FIELDS: usize = MAX_FIELDS + 1;
/// Longest field name reported, in bytes.
const MAX_NAME_BYTES: usize = 1024;

/// The aggregation expression that turns a sampled document into its field
/// names and BSON types, one list per nesting level: `{k, t}` of the top
/// level, `{p, k, t}` below it, `p` the parent's index in the list before.
/// A `$project` of it reads no value back. Its size is bounded whatever the
/// document: at most [`LEVEL_FIELDS`] entries a level, each name at most
/// [`MAX_NAME_BYTES`] (a longer one is `null`) — a document of many small
/// nested fields would otherwise outgrow the server's document limit and
/// fail the listing.
pub(super) fn field_types() -> Value {
    let levels: Vec<Value> = (1..=MAX_DEPTH).map(entries_of).collect();
    (1..=MAX_DEPTH).rev().fold(json!(levels), |inner, depth| {
        let fields = if depth == 1 {
            json!({ "$slice": [{ "$objectToArray": "$$ROOT" }, LEVEL_FIELDS] })
        } else {
            children_of(&format!("$$l{}", depth - 1))
        };
        json!({ "$let": { "vars": { (format!("l{depth}")): fields }, "in": inner } })
    })
}

/// The names and types of level `depth`'s fields, their values dropped.
fn entries_of(depth: usize) -> Value {
    let name = json!({ "$cond": [
        { "$gt": [{ "$strLenBytes": "$$f.k" }, MAX_NAME_BYTES] }, null, "$$f.k",
    ] });
    let mut entry = json!({ "k": name, "t": { "$type": "$$f.v" } });
    if depth > 1 {
        entry["p"] = json!("$$f.p");
    }
    json!({ "$map": { "input": format!("$$l{depth}"), "as": "f", "in": entry } })
}

/// The first [`LEVEL_FIELDS`] fields of the sub-documents among `parents`,
/// in order: no more is collected once that many are.
fn children_of(parents: &str) -> Value {
    let fields = json!({ "$map": {
        "input": { "$objectToArray": "$$parent.v" },
        "as": "child",
        "in": { "p": "$$this", "k": "$$child.k", "v": "$$child.v" },
    } });
    let collects = json!({ "$and": [
        { "$lt": [{ "$size": "$$value" }, LEVEL_FIELDS] },
        { "$eq": [{ "$type": "$$parent.v" }, "object"] },
    ] });
    let collected = json!({ "$reduce": {
        "input": { "$range": [0, { "$size": parents }] },
        "initialValue": [],
        "in": { "$let": {
            "vars": { "parent": { "$arrayElemAt": [parents, "$$this"] } },
            "in": { "$cond": [collects, { "$concatArrays": ["$$value", fields] }, "$$value"] },
        } },
    } });
    json!({ "$slice": [collected, LEVEL_FIELDS] })
}

/// `{sampled, fields: [{name, types, count}], truncated}` over the field
/// lists of the sampled documents (see [`field_types`]). `cut`: the sample
/// itself was cut short.
pub(super) fn infer_fields(documents: &[Value], cut: bool) -> Value {
    let mut inferred = Inferred {
        fields: BTreeMap::new(),
        truncated: cut,
    };
    for document in documents {
        inferred.add(document);
    }
    let truncated = inferred.truncated || inferred.fields.len() > MAX_FIELDS;
    let fields: Vec<Value> = inferred
        .fields
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

struct Inferred {
    fields: BTreeMap<String, Seen>,
    truncated: bool,
}

impl Inferred {
    /// Add one document's levels. A full level was cut, and a name left out
    /// takes its children with it; both leave the sample `truncated`.
    fn add(&mut self, levels: &Value) {
        let mut parents: Vec<Option<String>> = Vec::new();
        for level in levels.as_array().into_iter().flatten() {
            let entries = level.as_array().map_or(&[][..], Vec::as_slice);
            self.truncated |= entries.len() >= LEVEL_FIELDS;
            parents = entries
                .iter()
                .map(|entry| self.add_entry(entry, &parents))
                .collect();
        }
    }

    /// The entry's path, or `None` when it is left out.
    fn add_entry(&mut self, entry: &Value, parents: &[Option<String>]) -> Option<String> {
        let path = path_of(entry, parents);
        let (Some(path), Some(kind)) = (path, entry["t"].as_str()) else {
            self.truncated = true;
            return None;
        };
        let kind = type_name(kind);
        let seen = self.fields.entry(path.clone()).or_default();
        seen.count += 1;
        if !seen.types.iter().any(|known| known == kind) {
            seen.types.push(kind.to_string());
        }
        Some(path)
    }
}

fn path_of(entry: &Value, parents: &[Option<String>]) -> Option<String> {
    let key = entry["k"].as_str()?;
    if entry["p"].is_null() {
        return Some(key.to_string());
    }
    let parent = usize::try_from(entry["p"].as_u64()?).ok()?;
    let prefix = parents.get(parent)?.as_ref()?;
    Some(format!("{prefix}.{key}"))
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
                [
                    { "k": "_id", "t": "objectId" },
                    { "k": "email", "t": "string" },
                    { "k": "blob", "t": "binData" },
                    { "k": "address", "t": "object" },
                ],
                [{ "p": 3, "k": "geo", "t": "object" }],
                [{ "p": 0, "k": "lat", "t": "double" }],
            ]),
            json!([
                [{ "k": "_id", "t": "objectId" }, { "k": "email", "t": "null" }],
                [],
                [],
            ]),
        ];
        let inferred = infer_fields(&documents, false);
        assert_eq!(inferred["sampled"], 2);
        assert_eq!(
            inferred["fields"][0],
            json!({ "name": "_id", "types": ["objectId"], "count": 2 })
        );
        assert_eq!(types(&inferred, "email"), json!(["string", "null"]));
        assert_eq!(types(&inferred, "blob"), json!(["binary"]));
        assert_eq!(types(&inferred, "address"), json!(["object"]));
        assert_eq!(types(&inferred, "address.geo"), json!(["object"]));
        assert_eq!(types(&inferred, "address.geo.lat"), json!(["double"]));
        assert_eq!(inferred["truncated"], false);
        assert_eq!(infer_fields(&documents, true)["truncated"], true);
    }

    #[test]
    fn a_full_level_and_a_left_out_name_truncate_the_sample() {
        let wide: Vec<Value> = (0..LEVEL_FIELDS)
            .map(|_| json!({ "k": "same", "t": "int" }))
            .collect();
        let inferred = infer_fields(&[json!([wide])], false);
        assert_eq!(inferred["truncated"], true);

        let unnamed = json!([
            [{ "k": null, "t": "object" }, { "k": "kept", "t": "int" }],
            [{ "p": 0, "k": "child", "t": "int" }],
        ]);
        let inferred = infer_fields(&[unnamed], false);
        assert_eq!(inferred["fields"].as_array().map(Vec::len), Some(1));
        assert_eq!(inferred["fields"][0]["name"], "kept");
        assert_eq!(inferred["truncated"], true);
    }

    #[test]
    fn the_reported_fields_are_bounded() {
        let documents: Vec<Value> = (0..MAX_FIELDS + 1)
            .map(|i| json!([[{ "k": format!("f{i:04}"), "t": "int" }]]))
            .collect();
        let inferred = infer_fields(&documents, false);
        assert_eq!(
            inferred["fields"].as_array().map(Vec::len),
            Some(MAX_FIELDS)
        );
        assert_eq!(inferred["truncated"], true);
    }

    /// The expression is an ordinary read: the rejector takes it, and it
    /// opens exactly [`MAX_DEPTH`] levels.
    #[test]
    fn the_expression_passes_the_rejector_and_stops_at_the_depth_cap() {
        let expression = field_types();
        let command = json!({ "aggregate": "c", "pipeline": [
            { "$project": { "_id": 0, "levels": expression } },
        ], "cursor": {} });
        assert!(super::super::rejector::validate_command(&command.to_string()).is_ok());
        assert_eq!(
            expression.to_string().matches("$objectToArray").count(),
            MAX_DEPTH
        );
    }
}
