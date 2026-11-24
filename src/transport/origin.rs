//! `Origin` validation on the MCP endpoint (MCP 2025-06-18 Streamable HTTP:
//! servers MUST validate `Origin` to stop DNS rebinding, and answer a present
//! but invalid one with 403).
//!
//! A request with no `Origin` passes: non-browser agents never send one. A
//! present `Origin` passes only when it is in `MCP_ALLOWED_ORIGINS` or — with
//! the gateway bound to loopback — is itself a loopback origin. The check runs
//! before bearer auth, so a rejected request reaches no tool and writes no
//! audit row; it is logged instead — request id and reason only, never the
//! caller-written header, which may carry URL credentials.

use std::net::{IpAddr, SocketAddr};

use axum::Json;
use axum::extract::Request;
use axum::http::header::ORIGIN;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use url::{Host, Url};

use super::request_id::GatewayRequestId;
use crate::mcp::jsonrpc::{self, ErrorObject};

const ALLOWED_ORIGINS_VAR: &str = "MCP_ALLOWED_ORIGINS";

/// An `MCP_ALLOWED_ORIGINS` entry that is not a bare `http(s)://host[:port]`,
/// named by its 1-based position: the text itself may be a pasted URL with
/// credentials in it, so it is never kept.
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid {ALLOWED_ORIGINS_VAR} entry {entry}: expected a comma-separated list of \
     `https://host[:port]` origins (no userinfo, path, query or wildcard)"
)]
pub struct AllowedOriginsError {
    entry: usize,
}

/// Which browser origins may call the MCP endpoint. `Default` allows none,
/// which is also what a router built without this extension enforces.
#[derive(Debug, Clone, Default)]
pub struct AllowedOrigins {
    /// ASCII-serialized origins (`scheme://host[:port]`, default port elided).
    listed: Vec<String>,
    /// The gateway listens on loopback only, so a loopback origin is local.
    loopback_bind: bool,
}

impl AllowedOrigins {
    /// Read `MCP_ALLOWED_ORIGINS` (unset or blank → none listed).
    pub fn from_env(bind: SocketAddr) -> Result<Self, AllowedOriginsError> {
        let raw = std::env::var(ALLOWED_ORIGINS_VAR).unwrap_or_default();
        Self::parse(&raw, bind)
    }

    /// Parse a comma-separated origin list for a gateway bound to `bind`.
    pub fn parse(raw: &str, bind: SocketAddr) -> Result<Self, AllowedOriginsError> {
        let listed = if raw.trim().is_empty() {
            Vec::new()
        } else {
            raw.split(',')
                .enumerate()
                .map(|(index, entry)| {
                    parse_listed(entry.trim()).ok_or(AllowedOriginsError { entry: index + 1 })
                })
                .collect::<Result<_, _>>()?
        };
        Ok(Self {
            listed,
            loopback_bind: bind.ip().is_loopback(),
        })
    }

    fn allows(&self, origin: &str) -> bool {
        let Some(url) = parse_origin(origin) else {
            return false;
        };
        let serialized = url.origin().ascii_serialization();
        self.listed.contains(&serialized) || (self.loopback_bind && is_loopback_host(&url))
    }
}

fn parse_listed(entry: &str) -> Option<String> {
    parse_origin(entry).map(|url| url.origin().ascii_serialization())
}

/// An origin is `scheme://host[:port]` with an http(s) scheme, no userinfo,
/// path, query or fragment — the same rule for a listed entry and for an
/// incoming header. Anything else — `null` included — is not one.
fn parse_origin(raw: &str) -> Option<Url> {
    if !is_bare_origin(raw) {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    let plain = matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.path() == "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    plain.then_some(url)
}

/// The raw text is `scheme://authority` and nothing more. Checked before URL
/// parsing, which strips tabs and newlines, folds `\` into `/` and resolves
/// `/.` away — any of which would let a path pass as the bare `/`.
fn is_bare_origin(raw: &str) -> bool {
    let visible_ascii = raw.bytes().all(|byte| matches!(byte, 0x21..=0x7E));
    let Some((_, authority)) = raw.split_once("://") else {
        return false;
    };
    visible_ascii && !authority.is_empty() && !authority.contains(['/', '\\', '?', '#', '@'])
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// Middleware: 403 on a present `Origin` the policy does not allow.
pub(super) async fn check(req: Request, next: Next) -> Response {
    let default_policy = AllowedOrigins::default();
    let policy = req
        .extensions()
        .get::<AllowedOrigins>()
        .unwrap_or(&default_policy);
    let Some(reason) = refusal(req.headers(), policy) else {
        return next.run(req).await;
    };
    tracing::warn!(
        request_id = %GatewayRequestId::of(&req),
        reason,
        "rejected a request from a disallowed Origin"
    );
    (
        StatusCode::FORBIDDEN,
        Json(jsonrpc::Response::error(
            Value::Null,
            ErrorObject::invalid_request_with("Origin not allowed"),
        )),
    )
        .into_response()
}

/// Why `headers` must be refused, or `None` to let the request through. A
/// repeated `Origin` is refused outright: a browser sends one, and checking
/// only the first would let a disallowed second one ride along.
fn refusal(headers: &HeaderMap, policy: &AllowedOrigins) -> Option<&'static str> {
    let mut origins = headers.get_all(ORIGIN).iter();
    let first = origins.next()?;
    if origins.next().is_some() {
        return Some("repeated Origin header");
    }
    let allowed = first.to_str().is_ok_and(|origin| policy.allows(origin));
    (!allowed).then_some("Origin not allowed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_bind() -> SocketAddr {
        "0.0.0.0:8443".parse().unwrap()
    }

    fn loopback_bind() -> SocketAddr {
        "127.0.0.1:8443".parse().unwrap()
    }

    #[test]
    fn listed_origins_match_after_normalisation() {
        let policy = AllowedOrigins::parse(
            "https://Claude.AI, https://app.example.com:8443",
            public_bind(),
        )
        .unwrap();
        assert!(policy.allows("https://claude.ai"));
        assert!(policy.allows("https://claude.ai:443"));
        assert!(policy.allows("https://app.example.com:8443"));
        assert!(
            !policy.allows("http://claude.ai"),
            "scheme is part of the origin"
        );
        assert!(
            !policy.allows("https://app.example.com"),
            "port is part of it"
        );
        assert!(!policy.allows("https://evil.claude.ai"));
        assert!(!policy.allows("null"));
    }

    #[test]
    fn unset_allows_no_present_origin_on_a_public_bind() {
        let policy = AllowedOrigins::parse("  ", public_bind()).unwrap();
        assert!(!policy.allows("http://localhost:3000"));
        assert!(!policy.allows("https://claude.ai"));
    }

    #[test]
    fn loopback_bind_allows_loopback_origins_only() {
        let policy = AllowedOrigins::parse("", loopback_bind()).unwrap();
        assert!(policy.allows("http://localhost:6274"));
        assert!(policy.allows("http://127.0.0.1:3000"));
        assert!(policy.allows("http://[::1]:3000"));
        assert!(!policy.allows("http://localhost.evil.example"));
        assert!(!policy.allows("https://attacker.example"));
    }

    #[test]
    fn malformed_entries_fail_boot() {
        for bad in [
            "*",
            "claude.ai",
            "https://claude.ai/",
            "https://claude.ai/path",
            "https://claude.ai?x=1",
            "https://user@claude.ai",
            "ftp://claude.ai",
            "https://claude.ai,",
        ] {
            assert!(
                AllowedOrigins::parse(bad, public_bind()).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn a_rejected_entry_is_reported_by_position_not_text() {
        let err = AllowedOrigins::parse(
            "https://claude.ai, https://admin:hunter2@claude.ai",
            public_bind(),
        )
        .unwrap_err();
        for rendered in [err.to_string(), format!("{err:?}")] {
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(!rendered.contains("admin"), "{rendered}");
        }
        assert!(err.to_string().contains("entry 2"), "{err}");
    }

    #[test]
    fn an_incoming_origin_with_a_path_is_not_an_origin() {
        let policy = AllowedOrigins::parse("https://claude.ai", public_bind()).unwrap();
        for bad in [
            "https://claude.ai/",
            "https://claude.ai/path",
            "https://claude.ai/%2e%2e/x",
        ] {
            assert!(!policy.allows(bad), "{bad:?} allowed");
        }
        let loopback = AllowedOrigins::parse("", loopback_bind()).unwrap();
        assert!(!loopback.allows("http://localhost:3000/app"));
    }

    #[test]
    fn a_path_normalisation_would_erase_is_still_a_path() {
        let policy = AllowedOrigins::parse("https://claude.ai", public_bind()).unwrap();
        for bad in [
            "https://claude.ai/.",
            "https://claude.ai/..",
            "https://claude.ai\\",
            "https://claude.ai\n/x",
            "https://user:pw@claude.ai",
        ] {
            assert!(!policy.allows(bad), "{bad:?} allowed");
            assert!(
                AllowedOrigins::parse(bad, public_bind()).is_err(),
                "{bad:?} listed"
            );
        }
        // A listed entry is trimmed; an incoming header is taken as sent.
        for bad in ["https://claude.ai\t", "https://claude.ai "] {
            assert!(!policy.allows(bad), "{bad:?} allowed");
        }
    }

    fn origins(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(ORIGIN, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn a_repeated_origin_is_refused_even_when_the_first_is_allowed() {
        let policy = AllowedOrigins::parse("https://claude.ai", public_bind()).unwrap();
        assert_eq!(refusal(&origins(&[]), &policy), None);
        assert_eq!(refusal(&origins(&["https://claude.ai"]), &policy), None);
        assert_eq!(
            refusal(&origins(&["https://attacker.example"]), &policy),
            Some("Origin not allowed")
        );
        assert_eq!(
            refusal(
                &origins(&["https://claude.ai", "https://attacker.example"]),
                &policy
            ),
            Some("repeated Origin header")
        );
        assert_eq!(
            refusal(
                &origins(&["https://claude.ai", "https://claude.ai"]),
                &policy
            ),
            Some("repeated Origin header")
        );
    }
}
