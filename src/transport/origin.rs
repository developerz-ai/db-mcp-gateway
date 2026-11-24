//! `Origin` validation on the MCP endpoint (MCP 2025-06-18 Streamable HTTP:
//! servers MUST validate `Origin` to stop DNS rebinding, and answer a present
//! but invalid one with 403).
//!
//! A request with no `Origin` passes: non-browser agents never send one. A
//! present `Origin` passes only when it is in `MCP_ALLOWED_ORIGINS` or — with
//! the gateway bound to loopback — is itself a loopback origin. The check runs
//! before bearer auth, so a rejected request reaches no tool and writes no
//! audit row; it is logged instead.

use std::net::{IpAddr, SocketAddr};

use axum::Json;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::http::header::ORIGIN;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use url::{Host, Url};

use super::request_id::GatewayRequestId;
use crate::mcp::jsonrpc::{self, ErrorObject};

const ALLOWED_ORIGINS_VAR: &str = "MCP_ALLOWED_ORIGINS";
/// A rejected `Origin` is caller-controlled; the log keeps a bounded prefix.
const LOGGED_ORIGIN_MAX_BYTES: usize = 128;

/// An `MCP_ALLOWED_ORIGINS` entry that is not a bare `http(s)://host[:port]`.
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid {ALLOWED_ORIGINS_VAR} entry `{0}`: expected a comma-separated list of \
     `https://host[:port]` origins (no path, query or wildcard)"
)]
pub struct AllowedOriginsError(String);

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
                .map(|entry| parse_listed(entry.trim()))
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

fn parse_listed(entry: &str) -> Result<String, AllowedOriginsError> {
    let url = parse_origin(entry).ok_or_else(|| AllowedOriginsError(entry.to_owned()))?;
    Ok(url.origin().ascii_serialization())
}

/// An origin is `scheme://host[:port]` with an http(s) scheme, no userinfo,
/// path, query or fragment — the same rule for a listed entry and for an
/// incoming header. Anything else — `null` included — is not one.
fn parse_origin(raw: &str) -> Option<Url> {
    let url = Url::parse(raw).ok()?;
    let plain = matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.path() == "/"
        && !raw.ends_with('/')
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none();
    plain.then_some(url)
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
    let Some(origin) = req.headers().get(ORIGIN) else {
        return next.run(req).await;
    };
    let policy = req
        .extensions()
        .get::<AllowedOrigins>()
        .cloned()
        .unwrap_or_default();
    let origin = String::from_utf8_lossy(origin.as_bytes()).into_owned();
    if policy.allows(&origin) {
        return next.run(req).await;
    }
    tracing::warn!(
        request_id = %GatewayRequestId::of(&req),
        origin = prefix(&origin),
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

fn prefix(raw: &str) -> &str {
    let mut end = raw.len().min(LOGGED_ORIGIN_MAX_BYTES);
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    &raw[..end]
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
    fn logged_origin_is_bounded_on_a_char_boundary() {
        let long = "é".repeat(100);
        let cut = prefix(&long);
        assert!(cut.len() <= LOGGED_ORIGIN_MAX_BYTES);
        assert!(long.starts_with(cut));
    }
}
