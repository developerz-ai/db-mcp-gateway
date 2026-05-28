//! Transport layer: MCP over Streamable HTTP — a single endpoint where `GET`
//! opens the server→client SSE stream and `POST` carries client→server JSON-RPC.
//!
//! Owns framing + auth wiring: JSON-RPC parsing, method dispatch, SSE, and the
//! bearer-auth middleware on /mcp POST. DB execution and audit live elsewhere.
//! See docs/initial-idea/02-architecture.md.

pub mod app_state;
pub mod jsonrpc;
pub mod protocol;

mod auth_middleware;
mod auth_routes;
mod dispatch;
mod sse;

use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde_json::Value;

pub use app_state::{AppState, AuthFacade, PendingFlows};

use crate::auth::Identity;
use crate::config::Config;

/// Build the axum router, mounting the MCP endpoint and the auth routes.
pub fn router(config: &Config, state: AppState) -> Router {
    let path = normalize_path(&config.mcp_path);

    let mcp_post = post(post_handler).route_layer(middleware::from_fn_with_state(
        state.clone(),
        auth_middleware::bearer_auth,
    ));
    let mcp = Router::new().route(&path, get(sse::handler).merge(mcp_post));

    let auth = Router::new()
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/callback", get(auth_routes::callback))
        .route("/auth/logout", post(auth_routes::logout));

    mcp.merge(auth).with_state(state)
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
///
/// `Identity` is injected by `auth_middleware::bearer_auth` (or absent in tests
/// that bypass auth). It threads through to the audit layer in a later issue.
async fn post_handler(
    identity: Option<Extension<Identity>>,
    body: String,
) -> axum::response::Response {
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

    let user = identity
        .as_ref()
        .map(|i| i.user_sub.as_str())
        .unwrap_or("anonymous");
    tracing::debug!(method = %request.method, %user, "mcp request");

    match dispatch::dispatch(request) {
        Some(response) => Json(response).into_response(),
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
