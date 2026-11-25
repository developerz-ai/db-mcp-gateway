//! BSON → JSON rendering for tool responses.

use mongodb::bson::{Bson, Document, JavaScriptCodeWithScope, RawDocument};
use serde_json::{Map, Value};

use super::super::adapter::ExecError;

/// Convert a raw BSON document to a `serde_json::Value` using mongo's
/// relaxed extended JSON format. Plain scalars / arrays / docs map 1:1;
/// mongo-specific types (`ObjectId`, `Date`, `Decimal128`) render as the
/// standard `{ "$oid": ... }` / `{ "$date": ... }` shapes operators
/// expect — same rendering `mongosh` produces. Malformed BSON is the
/// driver's opaque failure.
pub(super) fn raw_to_json(raw: &RawDocument) -> Result<Value, ExecError> {
    let document = Document::try_from(raw).map_err(|_| ExecError::Sql)?;
    bson_to_json(Bson::Document(document))
}

/// A value that fails to serialize is an error, never a fabricated `null`
/// (which would read as a real BSON null). Every value that nests others —
/// documents, arrays, a code's scope — is walked here rather than by serde
/// because a JSON number cannot hold a NaN or an infinity: serde would render
/// one as `null`.
pub(super) fn bson_to_json(b: Bson) -> Result<Value, ExecError> {
    match b {
        Bson::Double(value) if !value.is_finite() => Ok(non_finite_double(value)),
        Bson::Document(document) => document_to_json(document),
        Bson::Array(items) => items
            .into_iter()
            .map(bson_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Bson::JavaScriptCodeWithScope(code) => code_to_json(code),
        other => serde_json::to_value(&other).map_err(|_| ExecError::Decode),
    }
}

// The two below are split out of `bson_to_json` so that a nesting level costs
// the stack only its own kind's frame.

fn document_to_json(document: Document) -> Result<Value, ExecError> {
    document
        .into_iter()
        .map(|(key, value)| Ok((key, bson_to_json(value)?)))
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}

/// Both parts are moved in: `json!` would serialize the rendered scope again,
/// once per nesting level.
fn code_to_json(code: JavaScriptCodeWithScope) -> Result<Value, ExecError> {
    let scope = document_to_json(code.scope)?;
    Ok(Value::Object(Map::from_iter([
        ("$code".to_owned(), Value::String(code.code)),
        ("$scope".to_owned(), scope),
    ])))
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
            bson_to_json(Bson::Document(doc)).expect("renders"),
            json!({
                "nan": { "$numberDouble": "NaN" },
                "inf": { "$numberDouble": "Infinity" },
                "ninf": { "$numberDouble": "-Infinity" },
                "nested": { "list": [1.5, { "$numberDouble": "NaN" }, { "deep": { "$numberDouble": "Infinity" } }] },
                "null": null,
            })
        );
    }

    /// The scope is the one value besides a document or an array that nests
    /// doubles; it must not fall back to serde's `null`.
    #[test]
    fn non_finite_doubles_in_a_code_scope_render_as_extended_json() {
        let code = Bson::JavaScriptCodeWithScope(JavaScriptCodeWithScope {
            code: "x".into(),
            scope: doc! {
                "nan": f64::NAN,
                "nested": [f64::NEG_INFINITY, { "deep": f64::INFINITY }],
                "inner": Bson::JavaScriptCodeWithScope(JavaScriptCodeWithScope {
                    code: "y".into(),
                    scope: doc! { "nan": f64::NAN, "n": 1 },
                }),
            },
        });
        assert_eq!(
            bson_to_json(Bson::Array(vec![code])).expect("renders"),
            json!([{
                "$code": "x",
                "$scope": {
                    "nan": { "$numberDouble": "NaN" },
                    "nested": [{ "$numberDouble": "-Infinity" }, { "deep": { "$numberDouble": "Infinity" } }],
                    "inner": { "$code": "y", "$scope": { "nan": { "$numberDouble": "NaN" }, "n": 1 } },
                },
            }])
        );
    }

    /// 200 levels is the server's default nesting limit, on a worker thread's
    /// stack and in an unoptimised build.
    #[test]
    fn scopes_nested_to_the_servers_limit_render_in_order() {
        const LEVELS: usize = 200;
        let rendered = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let nested = (0..LEVELS).fold(doc! { "nan": f64::NAN }, |scope, _| {
                    doc! { "z": 1, "c": Bson::JavaScriptCodeWithScope(JavaScriptCodeWithScope { code: "x".into(), scope }) }
                });
                let mut value = &bson_to_json(Bson::Document(nested)).expect("renders");
                for _ in 0..LEVELS {
                    let code = value["c"].as_object().expect("a code object");
                    assert!(code.keys().eq(["$code", "$scope"]));
                    value = &code["$scope"];
                }
                value.clone()
            })
            .expect("spawns")
            .join();
        assert_eq!(
            rendered.expect("the stack holds"),
            json!({ "nan": { "$numberDouble": "NaN" } })
        );
    }

    /// The walk keeps serde's rendering for everything else, key order
    /// included.
    #[test]
    fn other_values_keep_their_extended_json_shape() {
        let oid = ObjectId::parse_str("507f1f77bcf86cd799439011").expect("oid");
        let doc = doc! { "z": 1_i32, "a": 2_i64, "id": oid, "s": "x", "f": -0.25 };
        let rendered = bson_to_json(Bson::Document(doc)).expect("renders");
        assert_eq!(
            rendered,
            json!({ "z": 1, "a": 2, "id": { "$oid": "507f1f77bcf86cd799439011" }, "s": "x", "f": -0.25 })
        );
        let keys: Vec<_> = rendered.as_object().expect("object").keys().collect();
        assert_eq!(keys, ["z", "a", "id", "s", "f"]);
    }
}
