//! Transport layer: MCP over Streamable HTTP — a single endpoint where `GET`
//! opens the server→client SSE stream and `POST` carries client→server JSON-RPC.
//!
//! This layer owns framing only: JSON-RPC parsing, method dispatch, SSE. No auth,
//! no DB, no audit — those are separate layers. See
//! docs/initial-idea/02-architecture.md.

pub mod jsonrpc;
pub mod protocol;

mod dispatch;
mod sse;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::Value;

use crate::config::Config;

/// Build the axum router, mounting the MCP endpoint at the configured path.
pub fn router(config: &Config) -> Router {
    let path = normalize_path(&config.mcp_path);
    Router::new().route(&path, get(sse::handler).post(post_handler))
}

/// axum routes require a leading slash; tolerate config that omits it.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Handle one client→server JSON-RPC message.
async fn post_handler(body: String) -> axum::response::Response {
    let request = match serde_json::from_str::<jsonrpc::Request>(&body) {
        Ok(request) if request.jsonrpc == jsonrpc::JSONRPC_VERSION => request,
        Ok(request) => {
            let id = request.id.unwrap_or(Value::Null);
            return Json(jsonrpc::Response::error(
                id,
                jsonrpc::ErrorObject::invalid_request(),
            ))
            .into_response();
        }
        Err(_) => {
            return Json(jsonrpc::Response::error(
                Value::Null,
                jsonrpc::ErrorObject::parse_error(),
            ))
            .into_response();
        }
    };

    // request_id/user/server/database span lands with auth + tools (issues #2, #3).
    tracing::debug!(method = %request.method, "mcp request");

    match dispatch::dispatch(request) {
        Some(response) => Json(response).into_response(),
        // Notifications expect no body; ack with 202.
        None => StatusCode::ACCEPTED.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_adds_leading_slash() {
        assert_eq!(normalize_path("mcp"), "/mcp");
        assert_eq!(normalize_path("/mcp"), "/mcp");
    }
}
