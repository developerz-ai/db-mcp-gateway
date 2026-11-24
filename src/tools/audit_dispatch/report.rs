//! What a completed dispatch reports besides its audit row: the per-call
//! counters and the single "tool dispatched" line (issue #14 field contract).

use crate::auth::Identity;

use super::metric_names::CallLabels;
use super::{AuditHeader, Outcome, OutcomeCode, RequestContext};

pub(super) struct Dispatched<'a> {
    pub(super) identity: &'a Identity,
    pub(super) request_ctx: &'a RequestContext,
    pub(super) header: &'a AuditHeader<'a>,
    pub(super) labels: &'a CallLabels,
}

impl Dispatched<'_> {
    /// Both carry `code` — the outcome the client saw. `upstream_*` are the
    /// caller's unverified claims, logged for correlation.
    pub(super) fn record(&self, outcome: &Outcome, code: OutcomeCode) {
        let access = if outcome.write.is_some() {
            "write"
        } else {
            "read"
        };
        self.labels.count(code, access);
        let (header, request_ctx) = (self.header, self.request_ctx);
        tracing::info!(
            request_id = %request_ctx.request_id,
            user_sub = %self.identity.user_sub,
            tool = %header.tool,
            server = header.server.unwrap_or(""),
            db = header.database.unwrap_or(""),
            outcome = code.as_str(),
            access,
            duration_ms = outcome.elapsed_ms.unwrap_or(0),
            upstream_run_id = request_ctx.upstream.run_id(),
            upstream_actor = request_ctx.upstream.actor(),
            "tool dispatched"
        );
    }
}
