//! BSON → JSON rendering for tool responses.

use mongodb::bson::{Bson, Document};
use serde_json::Value;

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
/// (which would read as a real BSON null).
pub(super) fn bson_to_json(b: Bson) -> Result<Value, ExecError> {
    serde_json::to_value(&b).map_err(|_| ExecError::Decode)
}
