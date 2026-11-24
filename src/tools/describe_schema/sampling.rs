//! Document sampling for Mongo's `detail: full`: whether the caller may
//! sample, how much, and what the audit row says was read.

use crate::config::{Action, Grant, ServerKind};

use super::super::ToolCtx;
use super::super::target::{ensure_reason, resolve_target};
use super::{Arguments, Detail, MAX_SAMPLE_DOCUMENTS};

/// How Mongo's `full` may sample documents: under the caller's `query_read`
/// grant, its reason rule and its constraints, at most
/// [`MAX_SAMPLE_DOCUMENTS`] per collection. `system.*` collections are never
/// sampled (the adapter withholds them).
#[derive(Debug, Clone, Copy)]
pub(super) struct Sampling {
    pub(super) documents: u32,
    pub(super) statement_timeout_ms: Option<u32>,
}

pub(super) fn document_sampling(
    ctx: ToolCtx<'_>,
    db_grants: &[Grant],
    args: &Arguments,
) -> Option<Sampling> {
    if args.detail != Detail::Full {
        return None;
    }
    let read = resolve_target(
        ctx,
        db_grants,
        Action::QueryRead,
        &args.server,
        &args.database,
    )?;
    if read.server.kind != ServerKind::Mongo {
        return None;
    }
    ensure_reason(&read.constraints, args.reason.as_deref()).ok()?;
    Some(Sampling {
        documents: read
            .constraints
            .row_limit
            .map_or(MAX_SAMPLE_DOCUMENTS, |limit| {
                limit.min(MAX_SAMPLE_DOCUMENTS)
            }),
        statement_timeout_ms: read.constraints.statement_timeout_ms,
    })
}

/// The smaller of two optional caps; an absent one does not cap.
pub(super) fn tightest(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The audited read of a `full` call that samples documents.
pub(super) fn sampled_read(read: &str, sampling: Sampling) -> String {
    format!(
        "{read} [detail=full, sampled ≤ {} docs per collection]",
        sampling.documents
    )
}
