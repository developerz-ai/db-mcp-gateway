//! The answers [`super::enforce`] gives: a shed request's rejection and an
//! admitted MCP request's budget headers.

use axum::Json;
use axum::extract::Request;
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::ShedScope;
use crate::mcp::jsonrpc::{ErrorObject, Response as JsonRpcResponse, SERVER_OVERLOADED};
use crate::transport::request_id::GatewayRequestId;

/// Coarse back-off hint: permits free the instant in-flight requests finish,
/// so a short delay is enough.
const RETRY_AFTER_S: u64 = 1;

/// The caller's per-identity cap, and what was left of it at admission.
const CONCURRENCY_LIMIT_HEADER: HeaderName = HeaderName::from_static("x-dbmcp-concurrency-limit");
const CONCURRENCY_REMAINING_HEADER: HeaderName =
    HeaderName::from_static("x-dbmcp-concurrency-remaining");

pub(super) fn insert_budget(response: &mut Response, limit: usize, remaining: usize) {
    let headers = response.headers_mut();
    headers.insert(CONCURRENCY_LIMIT_HEADER, HeaderValue::from(limit));
    headers.insert(CONCURRENCY_REMAINING_HEADER, HeaderValue::from(remaining));
}

/// Stable-coded rejection: on the MCP endpoint a JSON-RPC error carrying the
/// code in `data`; elsewhere the `{ error: { category, code } }` shape the
/// auth middleware returns, plus the request id.
pub(super) fn limited(req: &Request, scope: ShedScope, mcp: bool) -> Response {
    let (status, category, code) = match scope {
        ShedScope::Identity => (
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "concurrency_limit_exceeded",
        ),
        ShedScope::Global | ShedScope::Oauth => (
            StatusCode::SERVICE_UNAVAILABLE,
            "overloaded",
            "service_overloaded",
        ),
    };
    let request_id = GatewayRequestId::of(req);
    tracing::warn!(
        %request_id,
        scope = scope.as_str(),
        path = req.uri().path(),
        "request shed by concurrency cap"
    );
    metrics::counter!("requests_shed_total", "scope" => scope.as_str()).increment(1);
    let mut response = if mcp {
        let error = ErrorObject::with_data(
            SERVER_OVERLOADED,
            shed_message(scope),
            json!({
                "code": code,
                "category": category,
                "retry_after_s": RETRY_AFTER_S,
                "request_id": request_id.to_string(),
            }),
        );
        // The body was never read, so its id is unknown: JSON-RPC says null.
        (status, Json(JsonRpcResponse::error(Value::Null, error))).into_response()
    } else {
        let body = json!({
            "error": { "category": category, "code": code },
            "request_id": request_id.to_string(),
        });
        (status, Json(body)).into_response()
    };
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(RETRY_AFTER_S));
    response
}

fn shed_message(scope: ShedScope) -> String {
    let what = match scope {
        ShedScope::Identity => "too many of your requests are in flight",
        ShedScope::Global | ShedScope::Oauth => "the gateway is at capacity",
    };
    format!("{what}; retry after {RETRY_AFTER_S} s")
}
