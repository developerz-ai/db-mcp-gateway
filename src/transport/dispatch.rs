//! Routes a parsed, id-checked JSON-RPC request to its stateless MCP method.
//!
//! Pure and synchronous — no I/O, fully unit-testable. Notifications and the
//! id rule are handled before this point (`mcp_handler`), and `tools/call`
//! goes to `crate::tools` instead.

use serde_json::Value;

use crate::mcp::jsonrpc::{ErrorObject, Response};
use crate::mcp::protocol::{EmptyResult, InitializeResult, TOOLS_LIST};

pub fn dispatch(id: Value, method: &str) -> Response {
    match method {
        "initialize" => Response::result(id, &InitializeResult::new()),
        // A notification by definition; if a client (wrongly) sends it with an
        // `id`, it's a request and JSON-RPC requires we answer rather than hang it.
        "notifications/initialized" => Response::error(id, ErrorObject::invalid_request()),
        "ping" => Response::result(id, &EmptyResult {}),
        "tools/list" => Response::result(id, &*TOOLS_LIST),
        other => Response::error(id, ErrorObject::method_not_found(other)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mcp::jsonrpc::{INVALID_REQUEST, METHOD_NOT_FOUND};
    use crate::mcp::protocol;

    fn dispatch_value(id: Value, method: &str) -> Value {
        serde_json::to_value(dispatch(id, method)).unwrap()
    }

    #[test]
    fn initialize_reports_protocol_version_and_identity() {
        let value = dispatch_value(json!(1), "initialize");
        assert_eq!(
            value["result"]["protocolVersion"],
            protocol::PROTOCOL_VERSION
        );
        assert_eq!(value["result"]["serverInfo"]["name"], protocol::SERVER_NAME);
    }

    #[test]
    fn initialized_with_an_id_is_invalid_request() {
        let value = dispatch_value(json!(9), "notifications/initialized");
        assert_eq!(value["error"]["code"], INVALID_REQUEST);
        assert_eq!(value["id"], 9);
    }

    #[test]
    fn unknown_method_is_method_not_found() {
        let value = dispatch_value(json!(7), "does/not/exist");
        assert_eq!(value["error"]["code"], METHOD_NOT_FOUND);
        assert_eq!(value["id"], 7);
    }

    #[test]
    fn tools_list_advertises_list_servers() {
        let value = dispatch_value(json!(4), "tools/list");
        assert_eq!(
            value["result"]["tools"][0]["name"],
            protocol::LIST_SERVERS_TOOL
        );
    }

    /// `additionalProperties: false` hides any argument the schema omits, so
    /// history pagination must be advertised explicitly.
    #[test]
    fn get_query_history_advertises_cursor_reason_and_limit_ceiling() {
        let value = dispatch_value(json!(5), "tools/list");
        let history = value["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == protocol::GET_QUERY_HISTORY_TOOL)
            .expect("get_query_history advertised");
        let props = &history["inputSchema"]["properties"];
        assert_eq!(props["cursor"]["type"], "string");
        assert_eq!(props["limit"]["maximum"], 1000);
        assert_eq!(props["reason"]["type"], "string");
    }
}
