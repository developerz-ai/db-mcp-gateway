//! BSON → JSON rendering for tool responses.

use mongodb::bson::{Bson, Document};
use serde_json::{Map, Value};

use super::super::adapter::ExecError;

/// Convert a `bson::Document` to a `serde_json::Value` using mongo's
/// relaxed extended JSON format. Plain scalars / arrays / docs map 1:1;
/// mongo-specific types (`ObjectId`, `Date`, `Decimal128`) render as the
/// standard `{ "$oid": ... }` / `{ "$date": ... }` shapes operators
/// expect — same rendering `mongosh` produces.
pub(super) fn doc_to_json(doc: Document) -> Result<Value, ExecError> {
    bson_to_json(Bson::Document(doc))
}

/// A value that fails to serialize is an error, never a fabricated `null`
/// (which would read as a real BSON null). Documents and arrays are walked
/// here rather than by serde because a JSON number cannot hold a NaN or an
/// infinity: serde would render one as `null`.
pub(super) fn bson_to_json(b: Bson) -> Result<Value, ExecError> {
    match b {
        Bson::Double(value) if !value.is_finite() => Ok(non_finite_double(value)),
        Bson::Document(doc) => doc
            .into_iter()
            .map(|(key, value)| Ok((key, bson_to_json(value)?)))
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
        Bson::Array(items) => items
            .into_iter()
            .map(bson_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => serde_json::to_value(&other).map_err(|_| ExecError::Decode),
    }
}

/// Extended JSON's spelling of a double JSON has no number for — the same in
/// the relaxed and the canonical format.
fn non_finite_double(value: f64) -> Value {
    let text = if value.is_nan() {
        "NaN"
    } else if value.is_sign_positive() {
        "Infinity"
    } else {
        "-Infinity"
    };
    serde_json::json!({ "$numberDouble": text })
}

#[cfg(test)]
mod tests {
    use mongodb::bson::{doc, oid::ObjectId};
    use serde_json::json;

    use super::*;

    #[test]
    fn non_finite_doubles_render_as_extended_json_never_null() {
        let doc = doc! {
            "nan": f64::NAN,
            "inf": f64::INFINITY,
            "ninf": f64::NEG_INFINITY,
            "nested": { "list": [1.5, f64::NAN, { "deep": f64::INFINITY }] },
            "null": Bson::Null,
        };
        assert_eq!(
            doc_to_json(doc).expect("renders"),
            json!({
                "nan": { "$numberDouble": "NaN" },
                "inf": { "$numberDouble": "Infinity" },
                "ninf": { "$numberDouble": "-Infinity" },
                "nested": { "list": [1.5, { "$numberDouble": "NaN" }, { "deep": { "$numberDouble": "Infinity" } }] },
                "null": null,
            })
        );
    }

    /// The walk keeps serde's rendering for everything else, key order
    /// included.
    #[test]
    fn other_values_keep_their_extended_json_shape() {
        let oid = ObjectId::parse_str("507f1f77bcf86cd799439011").expect("oid");
        let doc = doc! { "z": 1_i32, "a": 2_i64, "id": oid, "s": "x", "f": -0.25 };
        let rendered = doc_to_json(doc).expect("renders");
        assert_eq!(
            rendered,
            json!({ "z": 1, "a": 2, "id": { "$oid": "507f1f77bcf86cd799439011" }, "s": "x", "f": -0.25 })
        );
        let keys: Vec<_> = rendered.as_object().expect("object").keys().collect();
        assert_eq!(keys, ["z", "a", "id", "s", "f"]);
    }
}
