//! Last-resort panic boundary for every route. A handler that panics would
//! otherwise kill its connection task: the client sees a reset, not an
//! answer. Here it gets `500` with the JSON-RPC `internal` envelope and the
//! request id. Tool work has its own boundary inside `audit_dispatch`, which
//! also completes the audit row; this one covers everything around it.

use std::panic::AssertUnwindSafe;

use axum::Json;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures::FutureExt;
use serde_json::{Value, json};

use super::request_id::GatewayRequestId;
use crate::mcp::jsonrpc::{self, ErrorObject};

/// Axum middleware; layer it inside `request_id::assign` so the id is set.
pub(super) async fn catch_panic(req: Request, next: Next) -> Response {
    let request_id = GatewayRequestId::of(&req);
    let path = req.uri().path().to_owned();
    // The request future is dropped after a panic and never polled again.
    match AssertUnwindSafe(next.run(req)).catch_unwind().await {
        Ok(response) => response,
        Err(_) => {
            // The payload is not logged: it may quote request or target data.
            tracing::error!(%request_id, path, "handler panicked; answering 500");
            internal_error(request_id)
        }
    }
}

fn internal_error(request_id: GatewayRequestId) -> Response {
    let error = ErrorObject {
        data: Some(json!({ "code": "internal", "request_id": request_id.to_string() })),
        ..ErrorObject::internal("internal error")
    };
    let body = jsonrpc::Response::error(Value::Null, error);
    (StatusCode::INTERNAL_SERVER_ERROR, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::middleware;
    use axum::routing::post;
    use tower::ServiceExt;

    use super::*;
    use crate::transport::request_id::{self, REQUEST_ID_HEADER};

    async fn panics() -> Response {
        panic!("handler defect")
    }

    #[tokio::test]
    async fn a_panicking_handler_answers_500_internal_with_the_request_id() {
        let app = Router::new()
            .route("/mcp", post(panics))
            .layer(middleware::from_fn(catch_panic))
            .layer(middleware::from_fn(request_id::assign));
        let request = Request::post("/mcp").body(Body::empty()).expect("request");

        let response = app.oneshot(request).await.expect("a response, not a reset");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let header_id = response.headers()[REQUEST_ID_HEADER]
            .to_str()
            .expect("ascii")
            .to_owned();
        let body = to_bytes(response.into_body(), 4096).await.expect("body");
        let body: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["error"]["code"], jsonrpc::INTERNAL_ERROR);
        assert_eq!(body["error"]["data"]["code"], "internal");
        assert_eq!(body["error"]["data"]["request_id"], header_id);
        assert!(!body.to_string().contains("handler defect"));
    }
}
