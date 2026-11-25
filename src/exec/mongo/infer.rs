//! Field inference for `describe_schema` `detail: full` on Mongo: the field
//! paths and value types seen in a bounded sample of a collection's
//! documents. A collection has no declared schema, so this is the closest
//! answer — `count` says how many sampled documents held the field, so a
//! sparse field reads as sparse.
//!
//! Types are read from the raw BSON elements, never from their rendered
//! form: a subdocument shaped like an ObjectId's extended JSON (`{"$oid":
//! …}`) is an `object`, never mistaken for the type it mimics (#385). They
//! are read here and not by an aggregation expression because the server
//! cannot open the widest legal object: `$objectToArray` of it outgrows the
//! server's own document limit and fails the command.
//!
//! Only names and type names leave here, never a value.

use std::collections::BTreeMap;

use mongodb::bson::RawDocument;
use mongodb::bson::raw::RawBsonRef;
use mongodb::bson::spec::ElementType;
use serde_json::{Value, json};

use super::super::adapter::ExecError;

/// Nesting followed into sub-documents (`a.b.c`); deeper fields are
/// reported at this depth as `object`.
const MAX_DEPTH: usize = 3;
/// Distinct field paths reported per collection, in name order.
const MAX_FIELDS: usize = 200;
/// Fields read per nesting level of one document.
const LEVEL_FIELDS: usize = MAX_FIELDS + 1;
/// Longest field name reported, in bytes.
const MAX_NAME_BYTES: usize = 1024;

/// One document's `{fields: [[path, type]], truncated}`. Bounded whatever
/// the document: it stops at [`LEVEL_FIELDS`] fields a level, without
/// reading the rest.
pub(super) fn field_list(document: &RawDocument) -> Result<Value, ExecError> {
    let mut list = FieldList {
        fields: Vec::new(),
        left: [LEVEL_FIELDS; MAX_DEPTH],
        truncated: false,
    };
    list.walk(document, None, 0);
    Ok(json!({ "fields": list.fields, "truncated": list.truncated }))
}

struct FieldList {
    fields: Vec<(String, &'static str)>,
    /// Fields each level may still add.
    left: [usize; MAX_DEPTH],
    /// A field was left out: past a level's bound, its name too long, or
    /// its bytes malformed.
    truncated: bool,
}

impl FieldList {
    fn walk(&mut self, document: &RawDocument, parent: Option<&str>, depth: usize) {
        for element in document.iter_elements() {
            let (Ok(element), Some(left)) = (element, self.left[depth].checked_sub(1)) else {
                self.truncated = true;
                return;
            };
            self.left[depth] = left;
            let key = element.key().as_str();
            if key.len() > MAX_NAME_BYTES {
                self.truncated = true;
                continue;
            }
            let path = match parent {
                Some(parent) => format!("{parent}.{key}"),
                None => key.to_string(),
            };
            let kind = element.element_type();
            self.fields.push((path.clone(), type_name(kind)));
            if kind == ElementType::EmbeddedDocument && depth + 1 < MAX_DEPTH {
                match element.value() {
                    Ok(RawBsonRef::Document(child)) => self.walk(child, Some(&path), depth + 1),
                    _ => self.truncated = true,
                }
            }
        }
    }
}

/// `{sampled, fields: [{name, types, count}], truncated}` over the sampled
/// documents' [`field_list`]s. `cut`: the sample itself was cut short.
pub(super) fn infer_fields(lists: &[Value], cut: bool) -> Value {
    let mut fields: BTreeMap<&str, Seen<'_>> = BTreeMap::new();
    let mut truncated = cut;
    for (document, list) in lists.iter().enumerate() {
        truncated |= list["truncated"] != false;
        for field in list["fields"].as_array().into_iter().flatten() {
            let (Some(path), Some(kind)) = (field[0].as_str(), field[1].as_str()) else {
                truncated = true;
                continue;
            };
            let seen = fields.entry(path).or_default();
            // One document can spell a path twice (`a: {b: …}` and a literal
            // `a.b`, or a name stored twice): it holds the field once.
            if seen.last_document != Some(document) {
                seen.last_document = Some(document);
                seen.count += 1;
            }
            if !seen.types.contains(&kind) {
                seen.types.push(kind);
            }
        }
    }
    truncated |= fields.len() > MAX_FIELDS;
    let fields: Vec<Value> = fields
        .into_iter()
        .take(MAX_FIELDS)
        .map(|(name, seen)| json!({ "name": name, "types": seen.types, "count": seen.count }))
        .collect();
    json!({ "sampled": lists.len(), "fields": fields, "truncated": truncated })
}

#[derive(Default)]
struct Seen<'a> {
    /// Distinct type names, in first-seen order.
    types: Vec<&'a str>,
    /// Documents holding the field.
    count: usize,
    last_document: Option<usize>,
}

fn type_name(kind: ElementType) -> &'static str {
    match kind {
        ElementType::Double => "double",
        ElementType::String => "string",
        ElementType::EmbeddedDocument => "object",
        ElementType::Array => "array",
        ElementType::Binary => "binary",
        ElementType::Undefined => "undefined",
        ElementType::ObjectId => "objectId",
        ElementType::Boolean => "bool",
        ElementType::DateTime => "date",
        ElementType::Null => "null",
        ElementType::RegularExpression => "regex",
        ElementType::DbPointer => "dbPointer",
        ElementType::JavaScriptCode => "javascript",
        ElementType::JavaScriptCodeWithScope => "javascriptWithScope",
        ElementType::Symbol => "symbol",
        ElementType::Int32 => "int",
        ElementType::Int64 => "long",
        ElementType::Timestamp => "timestamp",
        ElementType::Decimal128 => "decimal",
        ElementType::MinKey => "minKey",
        ElementType::MaxKey => "maxKey",
    }
}

#[cfg(test)]
mod tests {
    use mongodb::bson::{Bson, Document, RawDocumentBuf, doc, oid::ObjectId};

    use super::*;

    fn inferred(documents: &[Document]) -> Value {
        let lists: Vec<Value> = documents
            .iter()
            .map(|document| {
                let raw = RawDocumentBuf::try_from(document).expect("encodes");
                field_list(&raw).expect("lists")
            })
            .collect();
        infer_fields(&lists, false)
    }

    fn types(inferred: &Value, name: &str) -> Value {
        inferred["fields"]
            .as_array()
            .and_then(|fields| fields.iter().find(|f| f["name"] == name))
            .map(|f| f["types"].clone())
            .unwrap_or(Value::Null)
    }

    #[test]
    fn paths_types_and_counts_never_values() {
        let inferred = inferred(&[
            doc! { "_id": ObjectId::new(), "email": "alice@example.com",
            "address": { "city": "Oslo", "geo": { "lat": 1.5, "deep": { "er": 1 } } } },
            doc! { "_id": ObjectId::new(), "email": Bson::Null,
            "mimic": { "$oid": "65f0c0ffee0000000000abcd" }, "big": 1_i64, "tags": ["a"] },
        ]);
        assert_eq!(inferred["sampled"], 2);
        assert_eq!(
            inferred["fields"][0],
            json!({ "name": "_id", "types": ["objectId"], "count": 2 })
        );
        assert_eq!(types(&inferred, "email"), json!(["string", "null"]));
        assert_eq!(types(&inferred, "address.geo.lat"), json!(["double"]));
        assert_eq!(types(&inferred, "address.geo.deep"), json!(["object"]));
        assert_eq!(types(&inferred, "address.geo.deep.er"), Value::Null);
        assert_eq!(types(&inferred, "mimic"), json!(["object"]));
        assert_eq!(types(&inferred, "mimic.$oid"), json!(["string"]));
        assert_eq!(types(&inferred, "big"), json!(["long"]));
        assert_eq!(types(&inferred, "tags"), json!(["array"]));
        assert_eq!(inferred["truncated"], false);
        for value in ["alice@example.com", "Oslo", "65f0c0ffee"] {
            assert!(!inferred.to_string().contains(value), "{value} leaked");
        }
    }

    #[test]
    fn a_path_spelled_twice_counts_its_document_once() {
        let inferred = inferred(&[
            doc! { "a": { "b": 1 }, "a.b": "x", "": { "x": 1 }, "x": true },
            doc! { "a.b": 1.5 },
        ]);
        let field = |name: &str, types: Value, count: usize| {
            assert_eq!(
                inferred["fields"]
                    .as_array()
                    .and_then(|fields| fields.iter().find(|f| f["name"] == name)),
                Some(&json!({ "name": name, "types": types, "count": count })),
                "{inferred}"
            );
        };
        field("a.b", json!(["int", "string", "double"]), 2);
        field(".x", json!(["int"]), 1);
        field("x", json!(["bool"]), 1);
    }

    #[test]
    fn a_level_past_its_bound_a_long_name_or_a_cut_sample_is_truncated() {
        let wide = |n: usize| -> Document {
            (0..n)
                .map(|i| (format!("f{i:03}"), Bson::Int32(1)))
                .collect()
        };
        assert_eq!(inferred(&[wide(MAX_FIELDS)])["truncated"], false);
        assert_eq!(inferred(&[wide(LEVEL_FIELDS + 1)])["truncated"], true);
        // Two parents share their children's level.
        let raw = RawDocumentBuf::try_from(&doc! { "a": wide(150), "b": wide(150) });
        let list = field_list(&raw.expect("encodes")).expect("lists");
        assert_eq!(list["truncated"], true);
        assert_eq!(
            list["fields"].as_array().map(Vec::len),
            Some(2 + LEVEL_FIELDS)
        );

        let named = inferred(&[doc! { "n".repeat(MAX_NAME_BYTES + 1): { "x": 1 }, "kept": 1 }]);
        assert_eq!(named["fields"].as_array().map(Vec::len), Some(1));
        assert_eq!(named["truncated"], true);
        assert_eq!(infer_fields(&[], true)["truncated"], true);
    }

    #[test]
    fn the_reported_fields_are_bounded_across_documents() {
        let documents: Vec<Document> = (0..=MAX_FIELDS)
            .map(|i| [(format!("f{i:04}"), Bson::Int32(1))].into_iter().collect())
            .collect();
        let inferred = inferred(&documents);
        assert_eq!(
            inferred["fields"].as_array().map(Vec::len),
            Some(MAX_FIELDS)
        );
        assert_eq!(inferred["truncated"], true);
    }
}
