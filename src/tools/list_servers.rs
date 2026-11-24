//! `list_servers` — the caller's visible servers, sans connection info.
//!
//! Per spec 03: returns logical name, kind, human description, and the
//! databases the caller sees there (the `list_databases` view, so one call
//! answers "where can I go and what may I do"). No host, port, role or
//! password. The output goes through a
//! `Serialize`-able view type that doesn't even have a `password` field —
//! leaking credentials is structurally impossible, not "remembered to strip".
//!
//! Audits every dispatch through `audit_dispatch` (spec 07: "every tool call
//! writes one row"). The audit row has `server`/`database`/`sql` all `None`
//! because `list_servers` doesn't address a target.

use std::time::Instant;

use serde::Serialize;
use serde_json::Value;

use crate::auth::Identity;
use crate::authz;
use crate::config::{ConfigFile, Grant};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, elapsed_ms_since, error_outcome, run_audited,
    success_outcome,
};
use super::list_databases::{SafeDatabaseView, visible_databases};

const TOOL_NAME: &str = "list_servers";

/// Credential-free server view returned over the wire.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SafeServerView {
    pub name: String,
    pub kind: &'static str,
    pub description: String,
    pub databases: Vec<SafeDatabaseView>,
}

#[derive(Debug, Serialize)]
struct ListServersResult {
    servers: Vec<SafeServerView>,
}

/// Takes no arguments; any the caller sends are ignored.
pub async fn run(ctx: ToolCtx<'_>, id: Value) -> Response {
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: None,
        database: None,
        sql: None,
        reason: None,
        db_type: None,
    };
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(id, ctx.identity, ctx.config, &grants)
    })
    .await
}

fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
) -> Outcome {
    let started = Instant::now();
    let servers: Vec<SafeServerView> = config
        .servers
        .iter()
        .filter(|s| authz::can_see_server_effective(identity, s, &config.permissions, db_grants))
        .map(|server| SafeServerView {
            name: server.name.clone(),
            kind: super::db_type_label(server.kind),
            description: server.description.clone(),
            databases: visible_databases(identity, config, db_grants, server),
        })
        .collect();
    let row_count = i64::try_from(servers.len()).unwrap_or(i64::MAX);

    let payload = match serde_json::to_string(&ListServersResult { servers }) {
        Ok(t) => t,
        Err(_) => {
            // Serialization of our safe-view types is infallible in practice,
            // but `expect` on the request path is banned (CLAUDE.md): degrade
            // to a typed internal error instead of panicking.
            return error_outcome(
                OutcomeCode::Internal,
                "tool.list_servers.serialization_failed",
            );
        }
    };

    let elapsed = Some(elapsed_ms_since(started));
    success_outcome(id, payload, elapsed, Some(row_count), Some(false))
}

#[cfg(test)]
#[path = "list_servers_tests.rs"]
mod tests;
