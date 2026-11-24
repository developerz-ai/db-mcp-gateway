//! `GET /admin/v1/openapi.json` — the hand-written OpenAPI 3.1 document of
//! this API. Static: `openapi_tests` holds it equal to the mounted routes
//! in both directions, so it cannot drift from the router.

use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};

pub const DOCUMENT: &str = include_str!("openapi.json");

pub async fn document() -> Response {
    let mut response = DOCUMENT.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

#[cfg(test)]
#[path = "openapi_tests.rs"]
mod tests;
