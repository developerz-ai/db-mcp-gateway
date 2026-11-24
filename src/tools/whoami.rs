//! `whoami` — the caller's own identity, groups, session expiry and
//! effective grants (spec 03). Never another identity's: everything comes
//! from the authenticated `ctx.identity` and its own DB-grant slice.
//!
//! No target call. A session-authenticated caller's expiry is read from the
//! state DB's `sessions` row; a service account has no session.

use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::auth::session::SERVICE_SUBJECT_PREFIX;
use crate::auth::{Identity, IdentityKind};
use crate::config::{ConfigFile, Grant};
use crate::mcp::jsonrpc::Response;

use super::ToolCtx;
use super::args::parse_arguments;
use super::audit_dispatch::{
    AuditHeader, Outcome, OutcomeCode, elapsed_ms_since, error_outcome, reject_arguments,
    run_audited, success_outcome,
};
use super::list_databases::{SafeDatabaseView, database_view};

const TOOL_NAME: &str = "whoami";

/// Takes none; an unknown key is `invalid_arguments` like every tool.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {}

#[derive(Debug, Serialize)]
struct WhoamiResult<'a> {
    sub: &'a str,
    email: &'a str,
    /// `sso` or `service`.
    auth: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_account: Option<&'a str>,
    groups: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    session_expires_at: Option<DateTime<Utc>>,
    /// Every `(server, database)` the caller holds any action on.
    grants: Vec<SafeDatabaseView>,
}

pub async fn run(ctx: ToolCtx<'_>, id: Value, arguments: Option<Value>) -> Response {
    let arguments = Some(arguments.unwrap_or_else(|| Value::Object(Default::default())));
    if let Err(message) = parse_arguments::<Arguments>(arguments) {
        return reject_arguments(ctx, id, TOOL_NAME, &message).await;
    }
    run_audited(
        ctx,
        id,
        AuditHeader::untargeted(TOOL_NAME),
        |id, grants| async move {
            let started = Instant::now();
            let expires_at = match session_expiry(ctx).await {
                Ok(expires_at) => expires_at,
                Err(outcome) => return *outcome,
            };
            compute_outcome(id, ctx.identity, ctx.config, &grants, expires_at, started)
        },
    )
    .await
}

/// `None` for a service account, which no session row backs.
async fn session_expiry(ctx: ToolCtx<'_>) -> Result<Option<DateTime<Utc>>, Box<Outcome>> {
    if ctx.identity.kind == IdentityKind::Service {
        return Ok(None);
    }
    let session_id = Uuid::from(ctx.identity.session_id);
    match crate::state::sessions::fetch(ctx.state_db, session_id).await {
        Ok(row) => Ok(row.map(|row| row.expires_at)),
        Err(err) => {
            tracing::error!(
                class = %crate::state::connect_error_class(&err),
                request_id = %ctx.request.request_id,
                "whoami session lookup failed"
            );
            Err(Box::new(error_outcome(
                OutcomeCode::Internal,
                "session lookup failed",
            )))
        }
    }
}

fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
    session_expires_at: Option<DateTime<Utc>>,
    started: Instant,
) -> Outcome {
    let grants: Vec<SafeDatabaseView> = config
        .servers
        .iter()
        .flat_map(|server| {
            server
                .databases
                .iter()
                .filter_map(move |db| database_view(identity, config, db_grants, server, db))
        })
        .collect();
    let row_count = i64::try_from(grants.len()).unwrap_or(i64::MAX);
    let (auth, service_account) = match identity.kind {
        IdentityKind::Sso => ("sso", None),
        IdentityKind::Service => (
            "service",
            identity.user_sub.strip_prefix(SERVICE_SUBJECT_PREFIX),
        ),
    };
    let result = WhoamiResult {
        sub: &identity.user_sub,
        email: &identity.user_email,
        auth,
        service_account,
        groups: &identity.groups,
        session_expires_at,
        grants,
    };
    let Ok(text) = serde_json::to_string(&result) else {
        return error_outcome(OutcomeCode::Internal, "failed to serialize result");
    };
    success_outcome(
        id,
        text,
        Some(elapsed_ms_since(started)),
        Some(row_count),
        Some(false),
    )
}

#[cfg(test)]
#[path = "whoami_tests.rs"]
mod tests;
