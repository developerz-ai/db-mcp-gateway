//! Routes a parsed JSON-RPC request to its MCP method handler.
//!
//! Pure and synchronous — no I/O, fully unit-testable. Auth, real tools, and
//! per-request audit spans arrive in later issues (#2, #3, #8).

use serde::Deserialize;
use serde_json::Value;

use super::jsonrpc::{ErrorObject, Request, Response};
use super::protocol::{self, CallToolResult, EmptyResult, InitializeResult, ToolsListResult};

/// Dispatch a request. Returns `Some(response)` for requests, `None` for
/// notifications (which by definition expect no reply).
pub fn dispatch(request: Request) -> Option<Response> {
    let Request {
        id, method, params, ..
    } = request;
    let is_notification = id.is_none();
    let response_id = || id.clone().unwrap_or(Value::Null);

    match method.as_str() {
        "initialize" => Some(Response::result(response_id(), &InitializeResult::new())),
        // A notification by definition; if a client (wrongly) sends it with an
        // `id`, it's a request and JSON-RPC requires we answer rather than hang it.
        "notifications/initialized" => {
            if is_notification {
                None
            } else {
                Some(Response::error(
                    response_id(),
                    ErrorObject::invalid_request(),
                ))
            }
        }
        "ping" => Some(Response::result(response_id(), &EmptyResult {})),
        "tools/list" => Some(Response::result(
            response_id(),
            &ToolsListResult::scaffold(),
        )),
        "tools/call" => Some(handle_tool_call(response_id(), params)),
        other => {
            if is_notification {
                None
            } else {
                Some(Response::error(
                    response_id(),
                    ErrorObject::method_not_found(other),
                ))
            }
        }
    }
}

fn handle_tool_call(id: Value, params: Option<Value>) -> Response {
    #[derive(Deserialize)]
    struct CallParams {
        name: String,
    }

    match params.and_then(|p| serde_json::from_value::<CallParams>(p).ok()) {
        Some(call) if call.name == protocol::PING_TOOL => {
            Response::result(id, &CallToolResult::text("pong"))
        }
        Some(call) => Response::error(
            id,
            ErrorObject::invalid_params(format!("unknown tool: {}", call.name)),
        ),
        None => Response::error(id, ErrorObject::invalid_params("missing or invalid `name`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::jsonrpc::{INVALID_PARAMS, METHOD_NOT_FOUND};
    use serde_json::json;

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

    #[test]
    fn ping_tool_returns_pong() {
        let response = dispatch_value(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ping"}}),
        );
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["result"]["content"][0]["text"], "pong");
        assert_eq!(value["result"]["isError"], false);
    }

    #[test]
    fn unknown_tool_is_invalid_params() {
        let response = dispatch_value(
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nope"}}),
        );
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["error"]["code"], INVALID_PARAMS);
    }

    #[test]
    fn tools_list_advertises_ping() {
        let response = dispatch_value(json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}));
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["result"]["tools"][0]["name"], protocol::PING_TOOL);
    }
}
