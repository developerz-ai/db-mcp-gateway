//! Typed errors for `/admin/v1/*` endpoints (#52).
//!
//! Maps to stable JSON shapes the spec ties to per-error HTTP codes. CLAUDE.md
//! non-negotiable #1: a response body NEVER embeds a sqlx error, a DSN, or
//! anything that traces back to target-DB credentials — every variant here
//! ends up as a hand-written, secret-free message.
//!
//! Each response carries the per-request id (when known) so operators can
//! paste it into Loki/dashboards. The middleware extracts/synthesizes the
//! id at the top of the request and stamps it onto every error it returns;
//! handlers thread `AdminActor.request_id` through `with_request_id` so the
//! happy-path id and the failure-path id agree.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Admin-API failure modes. Variants map 1:1 to stable JSON error codes:
/// `forbidden`, `unauthorized`, `not_found`, `invalid_request`, `internal`.
#[derive(Debug)]
pub enum AdminErrorKind {
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

/// Response-shaped admin error. The `request_id` is rendered into the JSON
/// body so an operator can paste it from a failing client and join it to the
/// matching tracing span / audit row.
#[derive(Debug)]
pub struct AdminError {
    kind: AdminErrorKind,
    request_id: Option<String>,
}

impl AdminError {
    const fn new(kind: AdminErrorKind) -> Self {
        Self {
            kind,
            request_id: None,
        }
    }

    pub const fn forbidden() -> Self {
        Self::new(AdminErrorKind::Forbidden)
    }

    pub const fn unauthorized() -> Self {
        Self::new(AdminErrorKind::Unauthorized)
    }

    pub const fn not_found() -> Self {
        Self::new(AdminErrorKind::NotFound)
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::new(AdminErrorKind::Invalid(msg.into()))
    }

    pub const fn internal() -> Self {
        Self::new(AdminErrorKind::Internal)
    }

    /// Stamp the per-request id onto this error. Idempotent — the most recent
    /// caller wins, which matches the handler pattern where the inner-most
    /// stage knows the actor and overwrites whatever default the middleware
    /// set up.
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    fn status(&self) -> StatusCode {
        match &self.kind {
            AdminErrorKind::Forbidden => StatusCode::FORBIDDEN,
            AdminErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            AdminErrorKind::NotFound => StatusCode::NOT_FOUND,
            AdminErrorKind::Invalid(_) => StatusCode::BAD_REQUEST,
            AdminErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match &self.kind {
            AdminErrorKind::Forbidden => "forbidden",
            AdminErrorKind::Unauthorized => "unauthorized",
            AdminErrorKind::NotFound => "not_found",
            AdminErrorKind::Invalid(_) => "invalid_request",
            AdminErrorKind::Internal => "internal",
        }
    }

    fn message(&self) -> String {
        match &self.kind {
            AdminErrorKind::Forbidden => "admin group required".to_string(),
            AdminErrorKind::Unauthorized => "authentication required".to_string(),
            AdminErrorKind::NotFound => "not found".to_string(),
            // The constructor of `Invalid` is responsible for not embedding
            // sensitive values — strings here are field-name level only.
            AdminErrorKind::Invalid(msg) => msg.clone(),
            AdminErrorKind::Internal => "internal error".to_string(),
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let mut err = json!({ "code": self.code(), "message": self.message() });
        if let Some(rid) = self.request_id.as_deref() {
            // Top-level `request_id` mirrors the audit-row column and the
            // tracing span field of the same name — operators paste it once
            // and grep all three.
            err.as_object_mut()
                .expect("constructed above as object")
                .insert("request_id".to_string(), json!(rid));
        }
        let body = json!({ "error": err });
        (self.status(), Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn response_includes_request_id_when_set() {
        let resp = AdminError::forbidden()
            .with_request_id("req-42")
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "forbidden");
        assert_eq!(body["error"]["request_id"], "req-42");
    }

    #[tokio::test]
    async fn response_omits_request_id_when_absent() {
        let resp = AdminError::internal().into_response();
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "internal");
        assert!(
            body["error"].get("request_id").is_none(),
            "absent id must not render an empty/null field"
        );
    }

    #[tokio::test]
    async fn invalid_renders_message_verbatim() {
        let resp = AdminError::invalid("user_email must be non-empty")
            .with_request_id("r1")
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "invalid_request");
        assert_eq!(body["error"]["message"], "user_email must be non-empty");
        assert_eq!(body["error"]["request_id"], "r1");
    }
}
