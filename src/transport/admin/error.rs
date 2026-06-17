//! Typed errors for `/admin/v1/*` endpoints (#52).
//!
//! Maps to stable JSON shapes the spec ties to per-error HTTP codes. CLAUDE.md
//! non-negotiable #1: a response body NEVER embeds a sqlx error, a DSN, or
//! anything that traces back to target-DB credentials — every variant here
//! ends up as a hand-written, secret-free message.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Admin-API failure modes. Variants map 1:1 to stable JSON error codes:
/// `forbidden`, `unauthorized`, `not_found`, `invalid_request`, `internal`.
#[derive(Debug)]
pub enum AdminError {
    /// Caller authenticated but is not in the configured admin group.
    Forbidden,
    /// Caller did not pass `bearer_auth` (or middleware ran without `auth`).
    Unauthorized,
    /// The requested entity does not exist (or is soft-deleted).
    NotFound,
    /// Request body fails validation (empty fields, malformed UUID, etc.).
    Invalid(String),
    /// Anything we can't classify — DB outage, audit-write failure, encoder
    /// bug. Logged with the source; the user-facing body is generic.
    Internal,
}

impl AdminError {
    fn status(&self) -> StatusCode {
        match self {
            AdminError::Forbidden => StatusCode::FORBIDDEN,
            AdminError::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminError::NotFound => StatusCode::NOT_FOUND,
            AdminError::Invalid(_) => StatusCode::BAD_REQUEST,
            AdminError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            AdminError::Forbidden => "forbidden",
            AdminError::Unauthorized => "unauthorized",
            AdminError::NotFound => "not_found",
            AdminError::Invalid(_) => "invalid_request",
            AdminError::Internal => "internal",
        }
    }

    fn message(&self) -> String {
        match self {
            AdminError::Forbidden => "admin group required".to_string(),
            AdminError::Unauthorized => "authentication required".to_string(),
            AdminError::NotFound => "not found".to_string(),
            // The constructor of `Invalid` is responsible for not embedding
            // sensitive values — strings here are field-name level only.
            AdminError::Invalid(msg) => msg.clone(),
            AdminError::Internal => "internal error".to_string(),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let body = json!({ "error": { "code": self.code(), "message": self.message() } });
        (self.status(), Json(body)).into_response()
    }
}
