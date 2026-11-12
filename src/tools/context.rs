//! Per-request state every tool handler reads. Built once by
//! `dispatch_call`; all fields are borrows, so it is `Copy`.

use sqlx::PgPool;

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
    pub permissions_cache: Option<&'a PermissionsCache>,
    /// `None` makes every dispatch refuse: no audit store, no tool call.
    pub state_db: Option<&'a PgPool>,
    pub request: &'a RequestContext,
}
