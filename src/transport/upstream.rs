//! Upstream attribution headers (spec 14 §Upstream attribution). Many agents
//! share one service token, so a call may name the run and the requester it
//! acts for. Both are CLAIMED: the gateway caps and stores them, never trusts
//! them for authz. SSO sessions carry a verified identity, so their headers are
//! ignored.

use axum::http::{HeaderMap, HeaderName};

use crate::auth::{Identity, IdentityKind, ServicePolicy};
use crate::tools::{Upstream, UpstreamClaim};

pub(super) const RUN_ID_HEADER: HeaderName = HeaderName::from_static("x-dbmcp-run-id");
pub(super) const ON_BEHALF_OF_HEADER: HeaderName = HeaderName::from_static("x-dbmcp-on-behalf-of");

/// Longest accepted header value. Room for a UUID, a URL-ish run key or an
/// email address; short enough that a row or a log line stays bounded.
pub(super) const UPSTREAM_MAX_BYTES: usize = 128;

const MALFORMED_RUN_ID: &str = "`x-dbmcp-run-id` must be one value of 1-128 characters from \
     [A-Za-z0-9._:@/+=-]";
const MALFORMED_ON_BEHALF_OF: &str = "`x-dbmcp-on-behalf-of` must be one value of 1-128 \
     characters from [A-Za-z0-9._:@/+=-]";
const UPSTREAM_REQUIRED: &str = "this service account requires the `x-dbmcp-run-id` and \
     `x-dbmcp-on-behalf-of` headers";

/// The verdict on one request's upstream headers. A malformed header is
/// refused rather than dropped, so a claim is never silently lost from the
/// audit row.
pub(super) fn from_headers(
    headers: &HeaderMap,
    identity: &Identity,
    policy: Option<&ServicePolicy>,
) -> Upstream {
    if identity.kind != IdentityKind::Service {
        return Upstream::Absent;
    }
    let run_id = match claimed(headers, &RUN_ID_HEADER) {
        Ok(value) => value,
        Err(()) => return Upstream::Rejected(MALFORMED_RUN_ID),
    };
    let actor = match claimed(headers, &ON_BEHALF_OF_HEADER) {
        Ok(value) => value,
        Err(()) => return Upstream::Rejected(MALFORMED_ON_BEHALF_OF),
    };
    let required = policy.is_some_and(|p| p.require_upstream);
    if required && (run_id.is_none() || actor.is_none()) {
        return Upstream::Rejected(UPSTREAM_REQUIRED);
    }
    if run_id.is_none() && actor.is_none() {
        return Upstream::Absent;
    }
    Upstream::Claimed(UpstreamClaim { run_id, actor })
}

/// `Ok(None)` when absent; `Err` when repeated, empty, overlong or outside the
/// charset.
fn claimed(headers: &HeaderMap, name: &HeaderName) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if value.is_empty() || value.len() > UPSTREAM_MAX_BYTES || !value.bytes().all(allowed) {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn allowed(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"._:@/+=-".contains(&byte)
}

#[cfg(test)]
#[path = "upstream_tests.rs"]
mod tests;
