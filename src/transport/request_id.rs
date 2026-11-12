//! One gateway-minted id per HTTP request.
//!
//! The outermost middleware ([`assign`]) mints a UUID, stores it as a request
//! extension and returns it as `x-request-id` on every response — success,
//! 401, 429, 503, 404, 405 alike. Everything downstream that names the request
//! (error bodies, the tool dispatch span, `audit_calls.request_id`, admin
//! errors) reads that extension, so a client-visible id always finds its log
//! line and audit row.
//!
//! A client may send its own `x-request-id`. It is kept as a separate
//! [`ClientRequestId`] for log correlation only — never the audit key, because
//! the caller controls it (reused, colliding or forged values are all
//! possible).

use std::fmt;

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Longest client-supplied id kept; longer values are dropped, not truncated,
/// so a log search never matches a prefix of something else.
const MAX_CLIENT_REQUEST_ID_LEN: usize = 128;

/// The gateway's id for one HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayRequestId(Uuid);

impl GatewayRequestId {
    fn mint() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(self) -> Uuid {
        self.0
    }

    /// The id [`assign`] stored on `req`. A router built without the
    /// middleware (unit-test routers) gets a fresh id instead.
    pub fn of(req: &Request) -> Self {
        req.extensions()
            .get::<Self>()
            .copied()
            .unwrap_or_else(Self::mint)
    }
}

impl fmt::Display for GatewayRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A caller-supplied `x-request-id`, accepted only when short and made of
/// `[A-Za-z0-9._:-]` — nothing that can break a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequestId(String);

impl ClientRequestId {
    fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let raw = headers.get(REQUEST_ID_HEADER)?.to_str().ok()?;
        let well_formed = !raw.is_empty()
            && raw.len() <= MAX_CLIENT_REQUEST_ID_LEN
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
        well_formed.then(|| Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Outermost middleware: mint the id, expose it to handlers, stamp it on the
/// response.
pub async fn assign(mut req: Request, next: Next) -> Response {
    let id = GatewayRequestId::mint();
    if let Some(client_id) = ClientRequestId::from_headers(req.headers()) {
        req.extensions_mut().insert(client_id);
    }
    req.extensions_mut().insert(id);
    let mut response = next.run(req).await;
    // A hyphenated UUID is always a valid header value.
    if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn client_request_id_accepts_conventional_ids() {
        for ok in ["abc-123", "trace.span:42", "A_b"] {
            assert_eq!(
                ClientRequestId::from_headers(&headers_with(ok)).map(|c| c.0),
                Some(ok.to_owned())
            );
        }
    }

    #[test]
    fn client_request_id_rejects_oversized_or_odd_values() {
        let long = "a".repeat(MAX_CLIENT_REQUEST_ID_LEN + 1);
        for bad in [long.as_str(), "", "has space", "quote\"d", "semi;colon"] {
            assert!(
                ClientRequestId::from_headers(&headers_with(bad)).is_none(),
                "{bad:?} must be dropped"
            );
        }
    }
}
