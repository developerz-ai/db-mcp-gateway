//! Per-request state every tool handler reads. Built once by
//! `dispatch_call`; all fields are borrows, so it is `Copy`.

use sqlx::PgPool;

use crate::audit::drain::DetachedTasks;
use crate::audit::stream::StreamSinks;
use crate::auth::Identity;
use crate::authz::PermissionsCache;
use crate::config::ConfigFile;
use crate::exec::AdapterRegistry;

use super::RequestContext;

#[derive(Debug, Clone, Copy)]
pub struct ToolCtx<'a> {
    /// The authenticated caller — the audit subject.
    pub identity: &'a Identity,
    pub config: &'a ConfigFile,
    pub registry: &'a AdapterRegistry,
    pub permissions_cache: &'a PermissionsCache,
    /// The audit store; also what `get_query_history` reads.
    pub state_db: &'a PgPool,
    /// Fed each audit row after its durable write.
    pub audit_sinks: &'a StreamSinks,
    /// Where detached audit work (the drop-guard fallback, sink deliveries)
    /// runs, so shutdown can drain it.
    pub detached: &'a DetachedTasks,
    pub request: &'a RequestContext,
}
