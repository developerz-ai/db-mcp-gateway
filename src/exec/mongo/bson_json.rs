//! BSON → JSON rendering for tool responses.

use mongodb::bson::{Bson, Document};
use serde_json::Value;

/// Convert a `bson::Document` to a `serde_json::Value` using mongo's
/// relaxed extended JSON format. Plain scalars / arrays / docs map 1:1;
/// mongo-specific types (`ObjectId`, `Date`, `Decimal128`) render as the
/// standard `{ "$oid": ... }` / `{ "$date": ... }` shapes operators
/// expect — same rendering `mongosh` produces. Falls back to `Value::Null`
/// if serialization fails (should be impossible for a `Document` we just
/// received from the driver).
pub(super) fn doc_to_json(doc: Document) -> Value {
    bson_to_json(Bson::Document(doc))
}

pub(super) fn bson_to_json(b: Bson) -> Value {
    // bson 3 routes through serde. The default Serialize impl produces the
    // relaxed extended JSON shape (`ObjectId` → `{ "$oid": "..." }`, etc.)
    // which matches what `mongosh` prints — operators reading the audit
    // row or the tool response see the same renderings they'd see at the
    // shell, with no ad-hoc translation in between.
    serde_json::to_value(&b).unwrap_or(Value::Null)
}
