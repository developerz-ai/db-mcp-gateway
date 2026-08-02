//! Routes a parsed JSON-RPC request to its MCP method handler.
//!
//! Pure and synchronous — no I/O, fully unit-testable. `tools/call` is handled
//! in `post_handler` instead because tools need access to identity and the
//! loaded config; everything else stays here.

use super::jsonrpc::{ErrorObject, Request, Response};
use super::protocol::{EmptyResult, InitializeResult, ToolsListResult};

/// Dispatch a stateless request. Returns `Some(response)` for requests, `None`
/// for notifications (which by definition expect no reply). `tools/call` is
/// not handled here — see `tools::dispatch_call` for the stateful path.
pub fn dispatch(request: Request) -> Option<Response> {
    let Request { id, method, .. } = request;

    // Per JSON-RPC 2.0, only an omitted `id` marks a notification — the reply
    // is suppressed regardless of method. An explicit `"id": null` is NOT a
    // notification; MCP treats it as invalid_request (handled just below).
    // Delegate the distinction to `RequestId` so this rule lives in one place.
    if id.is_notification() {
        return None;
    }

    let response_id = id.response_id();

    // MCP requires a non-null id on requests. Reject explicit null before we
    // do any method-specific work so misuse is caught uniformly.
    if id.is_null() {
        return Some(Response::error(response_id, ErrorObject::invalid_request()));
    }

    let response = match method.as_str() {
        "initialize" => Response::result(response_id, &InitializeResult::new()),
        // A notification by definition; if a client (wrongly) sends it with an
        // `id`, it's a request and JSON-RPC requires we answer rather than hang it.
        "notifications/initialized" => Response::error(response_id, ErrorObject::invalid_request()),
        "ping" => Response::result(response_id, &EmptyResult {}),
        "tools/list" => Response::result(response_id, &ToolsListResult::current()),
        // `tools/call` is routed elsewhere — see `super::post_handler`.
        "tools/call" => Response::error(
            response_id,
            ErrorObject::internal("tools/call must be routed via tools::dispatch_call"),
        ),
        other => Response::error(response_id, ErrorObject::method_not_found(other)),
    };

    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::jsonrpc::INTERNAL_ERROR;
    use crate::transport::jsonrpc::METHOD_NOT_FOUND;
    use crate::transport::protocol;
    use serde_json::{Value, json};

    fn dispatch_value(value: Value) -> Response {
        dispatch(serde_json::from_value(value).unwrap()).expect("expected a response")
    }

    #[test]
    fn initialize_reports_protocol_version_and_identity() {
        let response = dispatch_value(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        );
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["result"]["protocolVersion"],
            protocol::PROTOCOL_VERSION
        );
        assert_eq!(value["result"]["serverInfo"]["name"], protocol::SERVER_NAME);
    }

    #[test]
    fn initialized_notification_yields_no_response() {
        let notification = serde_json::from_value(
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .unwrap();
        assert!(dispatch(notification).is_none());
    }

    #[test]
    fn initialized_with_an_id_is_invalid_request() {
        let response = dispatch_value(
            json!({"jsonrpc": "2.0", "id": 9, "method": "notifications/initialized"}),
        );
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["error"]["code"],
            crate::transport::jsonrpc::INVALID_REQUEST
        );
        assert_eq!(value["id"], 9);
    }

    /// `"id": null` is neither a valid request id (MCP forbids null) nor a
    /// notification (only an omitted id qualifies). It must surface as
    /// invalid_request rather than being silently dropped like a notification.
    #[test]
    fn explicit_null_id_is_invalid_request_not_a_notification() {
        let response = dispatch_value(
            json!({"jsonrpc": "2.0", "id": null, "method": "initialize", "params": {}}),
        );
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["error"]["code"],
            crate::transport::jsonrpc::INVALID_REQUEST
        );
        assert_eq!(value["id"], Value::Null);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let response =
            dispatch_value(json!({"jsonrpc": "2.0", "id": 7, "method": "does/not/exist"}));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(value["id"], 7);
    }

    #[test]
    fn unknown_notification_is_silently_ignored() {
        let notification =
            serde_json::from_value(json!({"jsonrpc": "2.0", "method": "notifications/whatever"}))
                .unwrap();
        assert!(dispatch(notification).is_none());
    }

    /// `tools/call` reaches us here only if the post handler forgot to route
    /// it to `tools::dispatch_call`. Surfacing as an internal error makes the
    /// mistake loud rather than silently returning a wrong shape.
    #[test]
    fn tools_call_in_pure_dispatch_is_internal_error() {
        let response = dispatch_value(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_servers"}
        }));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["error"]["code"], INTERNAL_ERROR);
    }

    #[test]
    fn tools_list_advertises_list_servers() {
        let response = dispatch_value(json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(
            value["result"]["tools"][0]["name"],
            protocol::LIST_SERVERS_TOOL
        );
    }
}
