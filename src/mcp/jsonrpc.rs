//! JSON-RPC 2.0 framing for the MCP transport — the request/response envelope
//! every MCP message rides in. Pure data + (de)serialization, no I/O.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

/// The only JSON-RPC version we accept or emit.
pub const JSONRPC_VERSION: &str = "2.0";

// Standard JSON-RPC 2.0 error codes.
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// The JSON-RPC `id` member as observed on the wire.
///
/// A plain `Option<Value>` conflates two very different cases that MCP
/// treats separately:
/// - `Absent`: the `id` member was omitted — a JSON-RPC notification
///   (no response expected).
/// - `Null`: `"id": null` was explicitly present — invalid per MCP
///   (requests require a non-null id) and discouraged by JSON-RPC 2.0
///   (`SHOULD NOT` be null). Treated as an invalid request, never as a
///   notification.
/// - `Present`: any other JSON value. MCP defines `RequestId` as
///   `string | number`, so booleans / arrays / objects / fractional
///   numbers are still parsed into `Present` but rejected as
///   `invalid_request` at the transport boundary via
///   [`RequestId::is_invalid_type`]. The invalid value is preserved so
///   the error response can echo it back verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RequestId {
    #[default]
    Absent,
    Null,
    Present(Value),
}

impl RequestId {
    /// True only when the `id` member was omitted — the sole case that
    /// makes a message a JSON-RPC notification. Explicit null is not a
    /// notification; it is an invalid request.
    pub fn is_notification(&self) -> bool {
        matches!(self, RequestId::Absent)
    }

    /// True when `id` was present but explicitly `null` — invalid per
    /// MCP (§ requests require a non-null id).
    pub fn is_null(&self) -> bool {
        matches!(self, RequestId::Null)
    }

    /// True when `id` is `Present` with a JSON type MCP doesn't accept.
    ///
    /// MCP's `RequestId` is `string | number`; JSON-RPC 2.0 also says
    /// numbers `SHOULD NOT` be fractional. Booleans, arrays, objects, and
    /// fractional numbers therefore reach this method as `true`, and the
    /// transport rejects them with `invalid_request` before any
    /// method-specific work (mirrors `is_null` — both are "the parser
    /// accepted it, but the protocol doesn't"). Very large integers that
    /// overflow both `i64` and `u64` deserialize as `f64` and are also
    /// treated as fractional here; no real client uses ids that big.
    pub fn is_invalid_type(&self) -> bool {
        match self {
            RequestId::Present(Value::String(_)) => false,
            RequestId::Present(Value::Number(n)) => !(n.is_i64() || n.is_u64()),
            RequestId::Present(_) => true,
            _ => false,
        }
    }

    /// Id value to echo in a response envelope. Absent/Null both collapse
    /// to `Value::Null`, which is what JSON-RPC 2.0 mandates for error
    /// responses to requests whose id could not be determined.
    pub fn response_id(&self) -> Value {
        match self {
            RequestId::Present(v) => v.clone(),
            _ => Value::Null,
        }
    }
}

impl<'de> Deserialize<'de> for RequestId {
    /// Serde default is only invoked when the field is absent, so any call
    /// into this deserializer means the `id` member was present. Null vs.
    /// value must then be distinguished by the payload itself.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Value::deserialize(deserializer)? {
            Value::Null => RequestId::Null,
            other => RequestId::Present(other),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    /// `Absent` for notifications, `Null` for the invalid `"id": null`
    /// case, `Present(v)` for real requests. See [`RequestId`].
    #[serde(default)]
    pub id: RequestId,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl Request {
    pub fn is_notification(&self) -> bool {
        self.id.is_notification()
    }
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    pub id: Value,
    /// Already-serialised JSON: a tool result is rendered once, here, not
    /// first into a `Value` tree and then again into the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

impl Response {
    /// Build a success response, serializing `value`. Serialization of our static
    /// payloads can't realistically fail; if it ever did we degrade to an internal
    /// error rather than `unwrap`-ing and panicking the worker.
    pub fn result<T: Serialize>(id: Value, value: &T) -> Self {
        match serde_json::value::to_raw_value(value) {
            Ok(value) => Self {
                jsonrpc: JSONRPC_VERSION,
                id,
                result: Some(value),
                error: None,
            },
            Err(error) => Self::error(id, ErrorObject::internal(error.to_string())),
        }
    }

    pub fn error(id: Value, error: ErrorObject) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorObject {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorObject {
    pub fn parse_error() -> Self {
        Self::new(PARSE_ERROR, "Parse error")
    }

    pub fn invalid_request() -> Self {
        Self::new(INVALID_REQUEST, "Invalid request")
    }

    /// `invalid_request` with a reason the client can act on.
    pub fn invalid_request_with(message: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, message)
    }

    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }
}

#[cfg(test)]
#[path = "jsonrpc_tests.rs"]
mod tests;
