//! Streamable HTTP header rules for `POST <mcp_path>` (MCP 2025-06-18
//! §Transports): the body must be declared JSON, and a present
//! `MCP-Protocol-Version` must name the version the gateway negotiates.

use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderName};

use crate::mcp::protocol::PROTOCOL_VERSION;

const PROTOCOL_VERSION_HEADER: HeaderName = HeaderName::from_static("mcp-protocol-version");

/// `Content-Type: application/json`, case-insensitive, parameters (e.g.
/// `charset`) allowed. Every MCP SDK transport sends it; anything else is a
/// `415`.
pub(super) fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
}

/// Whether the `MCP-Protocol-Version` header is acceptable. Absent is allowed:
/// the spec has the server assume its backwards-compatible default rather than
/// refuse. Present, it must be exactly the one version `initialize` answers
/// with — the gateway never negotiates another — and appear once.
pub(super) fn is_supported_protocol_version(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(PROTOCOL_VERSION_HEADER).iter();
    match (values.next(), values.next()) {
        (None, _) => true,
        (Some(value), None) => value.as_bytes() == PROTOCOL_VERSION.as_bytes(),
        (Some(_), Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn with(name: HeaderName, values: &[&'static str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name.clone(), HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn content_type_must_be_json() {
        assert!(is_json_content_type(&with(
            CONTENT_TYPE,
            &["application/json"]
        )));
        assert!(is_json_content_type(&with(
            CONTENT_TYPE,
            &["Application/JSON ; charset=utf-8"]
        )));
        assert!(!is_json_content_type(&HeaderMap::new()));
        for bad in ["text/plain", "application/jsonx", "application/json-seq"] {
            assert!(!is_json_content_type(&with(CONTENT_TYPE, &[bad])), "{bad}");
        }
    }

    #[test]
    fn protocol_version_is_absent_or_the_negotiated_one() {
        assert!(is_supported_protocol_version(&HeaderMap::new()));
        assert!(is_supported_protocol_version(&with(
            PROTOCOL_VERSION_HEADER,
            &[PROTOCOL_VERSION]
        )));
        for bad in ["2025-03-26", "1999-01-01", "banana", ""] {
            assert!(
                !is_supported_protocol_version(&with(PROTOCOL_VERSION_HEADER, &[bad])),
                "{bad:?}"
            );
        }
        assert!(!is_supported_protocol_version(&with(
            PROTOCOL_VERSION_HEADER,
            &[PROTOCOL_VERSION, PROTOCOL_VERSION]
        )));
    }
}
