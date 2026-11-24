//! `list_databases` — the databases the caller is permitted to see, each with
//! what the caller may do there (spec 03). No connection info; pure config +
//! authz, no target call.
//!
//! With `server`: that server's databases. Server-existence non-leak: no
//! grant on ANY of its databases answers `forbidden` — never an empty list,
//! which would tell the caller "the server exists". Without `server`: every
//! visible database across servers; empty is then a fine answer, since no
//! name was probed.
//!
//! Also owns [`SafeDatabaseView`], the per-database view `list_servers` and
//! `whoami` reuse, so all three report the same thing for one database.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::Identity;
use crate::authz::effective::{HeldAction, held_actions};
use crate::config::{Action, ConfigFile, Database, Grant, Server, ServerKind};
use crate::exec::adapter::effective_timeout_ms;
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, elapsed_ms_since, error_outcome, reject_arguments,
    run_audited, success_outcome,
};
use super::target::effective_row_limit;

const TOOL_NAME: &str = "list_databases";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    #[serde(default)]
    pub server: Option<String>,
}

/// Credential-free database view returned over the wire — no role, no
/// password, no DSN.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SafeDatabaseView {
    pub server: String,
    pub name: String,
    pub description: String,
    pub kind: &'static str,
    /// Every action the caller holds here, `query_write` included.
    pub actions: Vec<&'static str>,
    /// Data writes are possible: a `query_write` grant on a Postgres
    /// database configured with a `write_role`.
    pub writes: bool,
    /// Every tool the caller can use here on this engine.
    pub tools: Vec<&'static str>,
    /// What each action's calls are held to. `query_write` has no entry: a
    /// write runs under `query_read`'s limits.
    pub limits: Vec<ActionLimits>,
}

/// The effective constraints of one held action, as its tools enforce them.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ActionLimits {
    pub action: &'static str,
    pub tools: Vec<&'static str>,
    pub require_reason: bool,
    /// Most rows one call can return (`query_read` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_limit: Option<u32>,
    /// Statement timeout every target call runs under (absent for
    /// `history_read`, which never reaches the target).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_timeout_ms: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ListDatabasesResult {
    databases: Vec<SafeDatabaseView>,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    // Every argument is optional, so a call may omit `arguments` entirely.
    let arguments = Some(arguments.unwrap_or_else(|| Value::Object(Default::default())));
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: args.server.as_deref(),
        database: None,
        sql: None,
        reason: None,
        db_type: args
            .server
            .as_deref()
            .and_then(|server| super::db_type_for_server(ctx.config, server)),
    };
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(id, ctx.identity, ctx.config, &grants, args)
    })
    .await
}

fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
    args: &Arguments,
) -> Outcome {
    let started = Instant::now();
    let databases = match args.server.as_deref() {
        Some(name) => {
            let listed = config
                .servers
                .iter()
                .find(|s| s.name == name)
                .map(|server| visible_databases(identity, config, db_grants, server))
                .unwrap_or_default();
            if listed.is_empty() {
                return error_outcome(OutcomeCode::Forbidden, "no grants for this server");
            }
            listed
        }
        None => config
            .servers
            .iter()
            .flat_map(|server| visible_databases(identity, config, db_grants, server))
            .collect(),
    };

    let row_count = i64::try_from(databases.len()).unwrap_or(i64::MAX);
    let Ok(text) = serde_json::to_string(&ListDatabasesResult { databases }) else {
        return error_outcome(OutcomeCode::Internal, "failed to serialize result");
    };
    let elapsed = Some(elapsed_ms_since(started));
    success_outcome(id, text, elapsed, Some(row_count), Some(false))
}

/// `server`'s databases `list_databases` shows: those the caller holds
/// `schema_read` on (`query_*` imply it). A `history_read`-only database
/// appears in `whoami` alone.
pub(super) fn visible_databases(
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
    server: &Server,
) -> Vec<SafeDatabaseView> {
    server
        .databases
        .iter()
        .filter_map(|db| database_view(identity, config, db_grants, server, db))
        .filter(|view| view.actions.contains(&action_label(Action::SchemaRead)))
        .collect()
}

/// The view of one database, or `None` when the caller holds no action on it.
pub(super) fn database_view(
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
    server: &Server,
    database: &Database,
) -> Option<SafeDatabaseView> {
    let held = held_actions(
        identity,
        &server.name,
        &database.name,
        &config.permissions,
        db_grants,
    );
    if held.is_empty() {
        return None;
    }
    let holds = |action| held.iter().any(|h| h.action == action);
    let writes = holds(Action::QueryWrite)
        && server.kind == ServerKind::Postgres
        && database.write_role.is_some();
    let limits: Vec<ActionLimits> = held
        .iter()
        .filter(|h| h.action != Action::QueryWrite)
        .map(|h| action_limits(server.kind, h))
        .collect();
    let mut tools: Vec<&'static str> = limits.iter().flat_map(|l| l.tools.clone()).collect();
    tools.sort_unstable();
    Some(SafeDatabaseView {
        server: server.name.clone(),
        name: database.name.clone(),
        description: database.description.clone(),
        kind: super::db_type_label(server.kind),
        actions: held.iter().map(|h| action_label(h.action)).collect(),
        writes,
        tools,
        limits,
    })
}

fn action_limits(kind: ServerKind, held: &HeldAction) -> ActionLimits {
    let constraints = &held.constraints;
    let reaches_target = held.action != Action::HistoryRead;
    ActionLimits {
        action: action_label(held.action),
        tools: tools_for(kind, held.action).to_vec(),
        require_reason: constraints.require_reason,
        // The same clamp `run_query`/`sample_table` apply to an unbounded ask.
        row_limit: (held.action == Action::QueryRead)
            .then(|| effective_row_limit(Some(u32::MAX), constraints.row_limit, u32::MAX)),
        statement_timeout_ms: reaches_target
            .then(|| effective_timeout_ms(constraints.statement_timeout_ms)),
    }
}

/// The tools `action` unlocks on `kind`: each tool's authz action, minus
/// those the engine answers `unsupported_backend`.
fn tools_for(kind: ServerKind, action: Action) -> &'static [&'static str] {
    use super::{
        CANCEL_QUERY, DB_ACTIVITY, DESCRIBE_SCHEMA, EXPLAIN, GET_QUERY_HISTORY, RUN_QUERY,
        SAMPLE_TABLE, TABLE_STATS,
    };
    match (action, kind) {
        (Action::HistoryRead, _) => &[GET_QUERY_HISTORY],
        (_, ServerKind::Mysql | ServerKind::Mssql) | (Action::QueryWrite, _) => &[],
        (Action::SchemaRead, ServerKind::Postgres) => &[DESCRIBE_SCHEMA, TABLE_STATS, DB_ACTIVITY],
        (Action::SchemaRead, ServerKind::Mongo) => &[DESCRIBE_SCHEMA],
        (Action::SchemaRead, ServerKind::Redis) => &[],
        (Action::QueryRead, ServerKind::Postgres) => {
            &[RUN_QUERY, SAMPLE_TABLE, EXPLAIN, CANCEL_QUERY]
        }
        (Action::QueryRead, ServerKind::Mongo) => &[RUN_QUERY, SAMPLE_TABLE],
        (Action::QueryRead, ServerKind::Redis) => &[RUN_QUERY],
    }
}

/// The YAML spelling of `action`.
pub(super) fn action_label(action: Action) -> &'static str {
    match action {
        Action::SchemaRead => "schema_read",
        Action::QueryRead => "query_read",
        Action::QueryWrite => "query_write",
        Action::HistoryRead => "history_read",
    }
}

#[cfg(test)]
#[path = "list_databases_tests.rs"]
mod tests;
