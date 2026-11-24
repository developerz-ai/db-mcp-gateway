//! Entry points that load the caller's DB grants before dispatch.

use std::future::Future;
use std::sync::Arc;

use serde_json::Value;

use crate::config::Grant;
use crate::mcp::jsonrpc::Response;
use crate::tools::ToolCtx;

use super::{AuditHeader, Outcome, OutcomeCode, dispatch_in, error_outcome};

/// Load the caller's DB grants, then run `work` with them through
/// [`audit_dispatch`]. A grants-load failure still writes an audit row
/// (`internal`) — the work never runs, but the call is accounted for.
pub async fn run_audited<W, Fut>(
    ctx: ToolCtx<'_>,
    id: Value,
    header: AuditHeader<'_>,
    work: W,
) -> Response
where
    W: FnOnce(Value, Arc<Vec<Grant>>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    run_audited_with_params(ctx, id, header, None, work).await
}

/// [`run_audited`] for a call that binds positional `params`: the audit row
/// stores them (capped, see [`crate::audit::cap_stored_params`]) beside `sql`.
pub(in crate::tools) async fn run_audited_with_params<W, Fut>(
    ctx: ToolCtx<'_>,
    id: Value,
    header: AuditHeader<'_>,
    params: Option<&[Value]>,
    work: W,
) -> Response
where
    W: FnOnce(Value, Arc<Vec<Grant>>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    match load_grants(ctx).await {
        Ok(grants) => {
            let work = work(id.clone(), grants);
            dispatch_in(ctx, id, header, params, work).await
        }
        Err(outcome) => dispatch_in(ctx, id, header, params, async move { *outcome }).await,
    }
}

/// The caller's DB grants, for a tool whose audit header depends on them
/// (then [`run_with_grants`]). `Err` is the `internal` outcome to audit.
pub(in crate::tools) async fn load_grants(
    ctx: ToolCtx<'_>,
) -> Result<Arc<Vec<Grant>>, Box<Outcome>> {
    ctx.permissions_cache
        .get_for(ctx.identity)
        .await
        .map_err(|err| {
            tracing::error!(%err, "permissions cache load failed");
            Box::new(error_outcome(
                OutcomeCode::Internal,
                "permissions_cache_load_failed",
            ))
        })
}

/// [`run_audited`] with grants already loaded by [`load_grants`].
pub(in crate::tools) async fn run_with_grants<W, Fut>(
    ctx: ToolCtx<'_>,
    id: Value,
    header: AuditHeader<'_>,
    grants: Arc<Vec<Grant>>,
    work: W,
) -> Response
where
    W: FnOnce(Value, Arc<Vec<Grant>>) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let work = work(id.clone(), grants);
    dispatch_in(ctx, id, header, None, work).await
}
