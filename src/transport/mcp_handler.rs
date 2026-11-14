//! `POST <mcp_path>`: one client→server JSON-RPC message per request.
//!
//! Framing only — parse, apply the spec 02 id rule, then hand `tools/call` to
//! `crate::tools` and everything else to the pure [`super::dispatch`]. The
//! transport never evaluates a grant or runs SQL.

use std::convert::Infallible;
use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::header::{ALLOW, USER_AGENT};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::Value;

use super::app_state::McpState;
use super::dispatch;
use super::request_id::{ClientRequestId, GatewayRequestId};
use super::upstream;
use crate::auth::{Identity, ServicePolicy};
use crate::mcp::jsonrpc::{self, ErrorObject, Request, RequestId};
use crate::tools;

const TOOLS_CALL: &str = "tools/call";
const MCP_CLIENT_HEADER: HeaderName = HeaderName::from_static("x-mcp-client");

/// Who `bearer_auth` authenticated: the `Identity` (absent only on the
/// auth-less `test_router`) and, for a service token, its account policy.
#[derive(Debug)]
pub(super) struct Caller {
    identity: Option<Identity>,
    policy: Option<ServicePolicy>,
}

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        Ok(Self {
            identity: parts.extensions.get::<Identity>().cloned(),
            policy: parts.extensions.get::<ServicePolicy>().copied(),
        })
    }
}

/// Handle one JSON-RPC message.
pub(super) async fn post_handler(
    State(state): State<McpState>,
    Extension(request_id): Extension<GatewayRequestId>,
    client_request_id: Option<Extension<ClientRequestId>>,
    caller: Caller,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(rejection) => {
            let message = format!("request body could not be read: {}", rejection.body_text());
            return (
                rejection.status(),
                Json(jsonrpc::Response::error(
                    Value::Null,
                    ErrorObject::invalid_request_with(message),
                )),
            )
                .into_response();
        }
    };
    let request = match parse(&body) {
        Ok(request) => request,
        Err(response) => return Json(response).into_response(),
    };

    let Caller { identity, policy } = caller;
    let user_sub = identity
        .as_ref()
        .map_or("anonymous", |i| i.user_sub.as_str());
    tracing::debug!(
        method = %request.method,
        %user_sub,
        %request_id,
        client_request_id = client_request_id.as_ref().map(|c| c.as_str()),
        "mcp request"
    );

    let id = match checked_id(&request.id) {
        Ok(Some(id)) => id,
        Ok(None) => {
            // `tools/call` has no notification form: its outcome only reaches
            // the caller in the response body, so running it would execute a
            // query nobody can see (#136). Every notification is acknowledged
            // with 202 and nothing runs.
            if request.method == TOOLS_CALL {
                tracing::warn!(%user_sub, %request_id, "tools/call sent as a notification; declined");
            }
            return StatusCode::ACCEPTED.into_response();
        }
        Err(response) => {
            tracing::warn!(%user_sub, %request_id, method = %request.method, "rejected request id");
            return Json(response).into_response();
        }
    };

    if request.method != TOOLS_CALL {
        return Json(dispatch::dispatch(id, &request.method)).into_response();
    }

    // `bearer_auth` guarantees an identity on the production router; a
    // missing one is a defined internal error, never a panic.
    let Some(identity) = identity else {
        return Json(jsonrpc::Response::error(
            id,
            ErrorObject::internal("missing identity"),
        ))
        .into_response();
    };
    let request_ctx = tools::RequestContext {
        ip: connect_info.map(|ConnectInfo(addr)| addr.ip()),
        agent_client: agent_client(&headers),
        request_id: request_id.as_uuid(),
        upstream: upstream::from_headers(&headers, &identity, policy.as_ref()),
    };
    // One config / sink snapshot for the whole call, even across a reload.
    let config = state.config.load();
    let audit_sinks = state.audit_sinks.load();
    let ctx = tools::ToolCtx {
        identity: &identity,
        config: &config,
        registry: &state.adapter_registry,
        permissions_cache: &state.permissions_cache,
        state_db: &state.state_db,
        audit_sinks: &audit_sinks,
        detached: &state.detached,
        request: &request_ctx,
    };
    Json(tools::dispatch_call(id, ctx, request.params).await).into_response()
}

/// `GET <mcp_path>`: the gateway never initiates server→client messages, so
/// it offers no SSE stream (MCP 2025-06-18 Streamable HTTP permits `405`).
/// Answered before authentication — there is nothing behind it to protect.
pub(super) async fn get_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, "POST")]).into_response()
}

/// Parse a body into one JSON-RPC request. JSON that is not a single request
/// object is `invalid_request` (echoing the id when it can be recovered);
/// a batch array is refused explicitly — MCP 2025-06-18 removed batching.
fn parse(body: &[u8]) -> Result<Request, Box<jsonrpc::Response>> {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Err(rejection(Value::Null, ErrorObject::parse_error()));
    };
    if value.is_array() {
        return Err(rejection(
            Value::Null,
            ErrorObject::invalid_request_with("batch requests are not supported"),
        ));
    }
    let recovered_id = match value.get("id") {
        Some(id) if !id.is_null() => id.clone(),
        _ => Value::Null,
    };
    let invalid = || rejection(recovered_id.clone(), ErrorObject::invalid_request());
    if !value.is_object() {
        return Err(invalid());
    }
    let request: Request = serde_json::from_value(value).map_err(|_| invalid())?;
    if request.jsonrpc != jsonrpc::JSONRPC_VERSION {
        return Err(invalid());
    }
    Ok(request)
}

/// The caller's self-description for the audit row: `User-Agent`, else
/// `x-mcp-client`. Caller-controlled and copied into every audit row and
/// stream sink, so it is cut to the same 128-byte bound as the other upstream
/// headers, on a char boundary.
fn agent_client(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(USER_AGENT)
        .or_else(|| headers.get(MCP_CLIENT_HEADER))
        .and_then(|v| v.to_str().ok())?;
    let mut end = raw.len().min(upstream::UPSTREAM_MAX_BYTES);
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    Some(raw[..end].to_owned())
}

/// The spec 02 three-way id rule, in one place: an absent id is a
/// notification (`Ok(None)`); an explicit `null` or a type MCP does not allow
/// (`string | integer` only) is `invalid_request` before any method work; any
/// other id is echoed back.
fn checked_id(id: &RequestId) -> Result<Option<Value>, Box<jsonrpc::Response>> {
    match id {
        RequestId::Absent => Ok(None),
        RequestId::Null => Err(rejection(Value::Null, ErrorObject::invalid_request())),
        id if id.is_invalid_type() => {
            Err(rejection(id.response_id(), ErrorObject::invalid_request()))
        }
        RequestId::Present(value) => Ok(Some(value.clone())),
    }
}

fn rejection(id: Value, error: ErrorObject) -> Box<jsonrpc::Response> {
    Box::new(jsonrpc::Response::error(id, error))
}

#[cfg(test)]
#[path = "mcp_handler_tests.rs"]
mod tests;
