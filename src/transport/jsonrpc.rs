//! JSON-RPC 2.0 framing for the MCP transport — the request/response envelope
//! every MCP message rides in. Pure data + (de)serialization, no I/O.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
/// - `Present`: a valid id (string, number, or other JSON value).
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

impl Response {
    /// Build a success response, serializing `value`. Serialization of our static
    /// payloads can't realistically fail; if it ever did we degrade to an internal
    /// error rather than `unwrap`-ing and panicking the worker.
    pub fn result<T: Serialize>(id: Value, value: &T) -> Self {
        match serde_json::to_value(value) {
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
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_notification_by_missing_id() {
        let notification: Request =
            serde_json::from_value(json!({"jsonrpc": "2.0", "method": "x"})).unwrap();
        assert!(notification.is_notification());
        assert!(matches!(notification.id, RequestId::Absent));

        let request: Request =
            serde_json::from_value(json!({"jsonrpc": "2.0", "id": 1, "method": "x"})).unwrap();
        assert!(!request.is_notification());
        assert!(matches!(request.id, RequestId::Present(_)));
    }

    /// `"id": null` is *not* a notification — the member is present,
    /// just explicitly null, which MCP forbids for requests. Preserving
    /// presence lets the transport reject it as `invalid_request`
    /// instead of silently accepting it as a notification.
    #[test]
    fn distinguishes_explicit_null_id_from_absent_id() {
        let with_null: Request =
            serde_json::from_value(json!({"jsonrpc": "2.0", "id": null, "method": "x"})).unwrap();
        assert!(!with_null.is_notification());
        assert!(with_null.id.is_null());
        assert_eq!(with_null.id.response_id(), Value::Null);

        let absent: Request =
            serde_json::from_value(json!({"jsonrpc": "2.0", "method": "x"})).unwrap();
        assert!(absent.is_notification());
        assert!(!absent.id.is_null());
    }

    #[test]
    fn error_response_has_no_result() {
        let response = Response::error(json!(1), ErrorObject::method_not_found("foo"));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["error"]["code"], METHOD_NOT_FOUND);
        assert!(value.get("result").is_none());
    }

    #[test]
    fn success_response_has_no_error() {
        let response = Response::result(json!(1), &json!({ "ok": true }));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["result"]["ok"], true);
        assert!(value.get("error").is_none());
    }
}
