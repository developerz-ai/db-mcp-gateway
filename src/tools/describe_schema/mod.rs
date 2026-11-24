//! `describe_schema` — tables, columns and types of a database's schema.
//!
//! Action: `SchemaRead`. The adapter runs the catalog lookup; schema, table
//! and search term reach it as bound values, never interpolated identifiers.
//!
//! `detail` picks the shape: `names` (tables and their kind), `columns` (the
//! default, and the shape this tool always had), `full` (real types, keys,
//! indexes, comments, row estimates — see [`pg`]). Mongo answers collections
//! (see [`mongo`]); at `full` it also samples documents, which is row data,
//! so that part needs `query_read`.

mod mongo;
mod pg;

use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;

use crate::config::{Action, Grant, ServerKind};
use crate::exec::{Access, DbAdapter, ExecError, SchemaDetail, SchemaQuery};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, ToolErrorMessages, audit_outcome, error_outcome,
    invalid_arguments, outcome_from_exec_error, reject_arguments, run_audited, success_outcome,
};
use super::target::{Target, ensure_reason, forbidden, record_intent, resolve_target};

const TOOL_NAME: &str = "describe_schema";
const ERROR_MESSAGES: ToolErrorMessages = ToolErrorMessages {
    timeout: "catalog query exceeded statement_timeout",
    sql_rejected: "catalog query was rejected",
    forbidden_prefix: "catalog query",
};
const DEFAULT_SCHEMA: &str = "public";
/// One Postgres database can hold tens of thousands of columns across all
/// schemas. Cap the catalog query so a degenerate request can't dominate the
/// pool. Per-grant `row_limit` is *not* applied here — that constraint is
/// about user data, not catalog metadata.
const MAX_CATALOG_ROWS: u32 = 50_000;
/// Tables (or collections) at `detail: full`, each a row with its columns,
/// keys and indexes — or a document sample — inlined.
const MAX_FULL_TABLES: u32 = 2_000;
/// Documents sampled per collection at `detail: full` on Mongo, at most.
const MAX_SAMPLE_DOCUMENTS: u32 = 100;
const BLANK_SEARCH: &str = "`search` must not be blank";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arguments {
    pub server: String,
    pub database: String,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub table: Option<String>,
    #[serde(default)]
    pub detail: Detail,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// The caller's `detail`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detail {
    Names,
    #[default]
    Columns,
    Full,
}

impl Detail {
    fn schema_detail(self) -> SchemaDetail {
        match self {
            Self::Names => SchemaDetail::Names,
            Self::Columns => SchemaDetail::Columns,
            Self::Full => SchemaDetail::Full,
        }
    }
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let args: Arguments = match parse_arguments(arguments) {
        Ok(args) => args,
        Err(message) => return reject_arguments(ctx, id, TOOL_NAME, &message).await,
    };

    // The catalog read is scoped to a schema (and optionally one table);
    // that scope is what the audit row records as what was read: `*` when a
    // search spans every schema. Mongo has no schemas: the database is the
    // namespace. Redis has neither (and answers `unsupported_backend`), so
    // its read is the database.
    let db_type = super::db_type_for_server(ctx.config, &args.server);
    let schema = scope_schema(&args).unwrap_or("*");
    let read = match (db_type, args.table.as_deref()) {
        (Some("mongo"), Some(collection)) => format!("{}.{collection}", args.database),
        (Some("mongo" | "redis"), _) => args.database.clone(),
        (_, Some(table)) => format!("{schema}.{table}"),
        (_, None) => schema.to_string(),
    };
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: Some(&args.database),
        sql: Some(&read),
        reason: args.reason.as_deref(),
        db_type,
    };
    if args.search.as_deref().is_some_and(|s| s.trim().is_empty()) {
        let outcome = invalid_arguments(id.clone(), BLANK_SEARCH);
        return audit_outcome(ctx, id, header, outcome).await;
    }
    let args = &args;
    run_audited(ctx, id, header, |id, grants| async move {
        compute_outcome(ctx, id, &grants, &header, args).await
    })
    .await
}

/// The schema read: the caller's, else `public` — unless a search with no
/// schema spans them all (`None`).
fn scope_schema(args: &Arguments) -> Option<&str> {
    match (args.schema.as_deref(), args.search.as_deref()) {
        (Some(schema), _) => Some(schema),
        (None, Some(_)) => None,
        (None, None) => Some(DEFAULT_SCHEMA),
    }
}

async fn compute_outcome(
    ctx: ToolCtx<'_>,
    id: Value,
    db_grants: &[Grant],
    header: &AuditHeader<'_>,
    args: &Arguments,
) -> Outcome {
    let Some(target) = resolve_target(
        ctx,
        db_grants,
        Action::SchemaRead,
        &args.server,
        &args.database,
    ) else {
        return forbidden();
    };
    if let Err(rejected) = ensure_reason(&target.constraints, args.reason.as_deref()) {
        return *rejected;
    }
    let sampling = document_sampling(ctx, db_grants, &target, args);

    if let Err(refused) = record_intent(ctx, header, &target, Access::ReadOnly).await {
        return *refused;
    }

    // Wall clock starts before pool open so error paths still carry
    // `duration_ms` into the audit row — spec 07 requires it on every call.
    let started = Instant::now();
    let adapter = match ctx
        .registry
        .get_or_open(target.server, target.database)
        .await
    {
        Ok(a) => a,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };

    let mongo = target.server.kind == ServerKind::Mongo;
    let detail = match (args.detail, sampling) {
        // Without a grant to read documents, Mongo's `full` is `columns`.
        (Detail::Full, None) if mongo => Detail::Columns,
        (detail, _) => detail,
    };
    let row_limit = match detail {
        Detail::Full => MAX_FULL_TABLES,
        Detail::Names | Detail::Columns => MAX_CATALOG_ROWS,
    };
    let query = SchemaQuery {
        schema: scope_schema(args),
        table: args.table.as_deref(),
        search: args.search.as_deref(),
        detail: detail.schema_detail(),
        statement_timeout_ms: tightest(
            target.constraints.statement_timeout_ms,
            sampling.and_then(|s| s.statement_timeout_ms),
        ),
        row_limit,
        sample_limit: sampling.map_or(0, |s| s.documents),
        request_id: ctx.request.request_id,
    };
    let schemas = match (mongo, args.schema.is_none()) {
        (false, true) => match schema_names(adapter.as_ref(), &query).await {
            Ok(names) => Some(names),
            Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
        },
        _ => None,
    };
    let result = match adapter.describe_schema(query).await {
        Ok(result) => result,
        Err(err) => return outcome_from_exec_error(err, started, &ERROR_MESSAGES),
    };
    let elapsed = i64::try_from(result.elapsed_ms).unwrap_or(i64::MAX);
    let rendered = if mongo {
        let omitted = args.detail == Detail::Full && sampling.is_none();
        mongo::render(detail, &result, omitted)
    } else {
        pg::render(detail, &result, schemas)
    };
    let Ok((count, text)) = rendered else {
        return error_outcome(
            OutcomeCode::Internal,
            "catalog response shape changed unexpectedly",
        );
    };
    let count = i64::try_from(count).unwrap_or(i64::MAX);
    success_outcome(id, text, Some(elapsed), Some(count), Some(result.truncated))
}

/// How Mongo's `full` may sample documents: under the caller's `query_read`
/// grant, its reason rule and its constraints, at most
/// [`MAX_SAMPLE_DOCUMENTS`] per collection.
#[derive(Debug, Clone, Copy)]
struct Sampling {
    documents: u32,
    statement_timeout_ms: Option<u32>,
}

fn document_sampling(
    ctx: ToolCtx<'_>,
    db_grants: &[Grant],
    target: &Target<'_>,
    args: &Arguments,
) -> Option<Sampling> {
    if target.server.kind != ServerKind::Mongo || args.detail != Detail::Full {
        return None;
    }
    let read = resolve_target(
        ctx,
        db_grants,
        Action::QueryRead,
        &args.server,
        &args.database,
    )?;
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
fn tightest(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The schemas the read role may use, for a call that named none.
async fn schema_names(
    adapter: &dyn DbAdapter,
    query: &SchemaQuery<'_>,
) -> Result<Vec<String>, ExecError> {
    let listed = adapter
        .describe_schema(SchemaQuery {
            detail: SchemaDetail::Schemas,
            ..*query
        })
        .await?;
    Ok(listed
        .rows
        .iter()
        .filter_map(|row| row.first()?.as_str().map(str::to_owned))
        .collect())
}
