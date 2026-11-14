//! `tools/list` is a promise; the match in `tools::dispatch_call` is the only
//! thing that keeps it, and nothing in the type system ties the two together.
//!
//! That gap is not theoretical. #187 shipped `get_query_history`; #189 rebuilt
//! itself on a pre-#187 base and deleted the handler and its dispatch arm while
//! leaving the advertisement in `ToolsListResult::current()`. For two weeks the
//! gateway offered agents a tool that answered `unknown tool`, with CI green the
//! whole time (#212).
//!
//! Runs against the state DB, since every call — rejections included — is
//! audited. The second test pins that rejected calls (unknown tool, malformed
//! arguments) each leave an `invalid_arguments` row.

use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::audit::stream::StreamSinks;
use std::sync::Arc;
use std::time::Duration;

use db_mcp_gateway::auth::{Identity, SessionId};
use db_mcp_gateway::authz::PermissionsCache;
use db_mcp_gateway::config::ConfigFile;
use db_mcp_gateway::exec::AdapterRegistry;
use db_mcp_gateway::mcp::protocol::TOOLS_LIST;
use db_mcp_gateway::state::permissions::PermissionsRepo;
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::tools::{RequestContext, ToolCtx, Upstream, dispatch_call};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Everything a `ToolCtx` borrows, owned for the test's lifetime.
struct Fixture {
    identity: Identity,
    config: ConfigFile,
    registry: AdapterRegistry,
    pool: PgPool,
    cache: PermissionsCache,
    sinks: StreamSinks,
    tasks: DetachedTasks,
    request: RequestContext,
}

impl Fixture {
    async fn new() -> Self {
        let pool = state_pool().await;
        let repo: Arc<dyn PermissionsRepo> = Arc::new(PgPermissionsRepo::new(pool.clone()));
        Self {
            identity: identity(&format!("coverage-{}", Uuid::new_v4().simple())),
            config: ConfigFile::from_yaml_str("servers: []\n").expect("empty config parses"),
            registry: AdapterRegistry::new(),
            cache: PermissionsCache::new(repo, Duration::from_secs(30)),
            pool,
            sinks: StreamSinks::default(),
            tasks: DetachedTasks::new(),
            request: RequestContext {
                ip: None,
                agent_client: None,
                request_id: Uuid::new_v4(),
                upstream: Upstream::Absent,
            },
        }
    }

    fn ctx(&self) -> ToolCtx<'_> {
        ToolCtx {
            identity: &self.identity,
            config: &self.config,
            registry: &self.registry,
            permissions_cache: &self.cache,
            state_db: &self.pool,
            audit_sinks: &self.sinks,
            detached: &self.tasks,
            request: &self.request,
        }
    }

    async fn call(&self, params: Value) -> Value {
        let response = dispatch_call(json!(1), self.ctx(), Some(params)).await;
        serde_json::to_value(&response).expect("response serializes")
    }
}

fn identity(user_sub: &str) -> Identity {
    Identity {
        session_id: SessionId::new(),
        user_sub: user_sub.to_string(),
        user_email: "dev@example.com".to_string(),
        groups: vec!["engineers".to_string()],
        issued_at: chrono::Utc::now(),
        kind: db_mcp_gateway::auth::IdentityKind::Sso,
    }
}

/// Every name in `tools/list` must reach a real arm in `tools/call`.
///
/// Deliberately asserts nothing about what each tool *does* with empty
/// arguments — that varies (`invalid_params` for a missing `server`, an
/// audit-unavailable error with no state DB) and is each tool's own test's
/// business. The single claim is that no advertised name falls through to the
/// catch-all.
#[tokio::test]
async fn every_advertised_tool_has_a_dispatch_arm() {
    let fixture = Fixture::new().await;

    // Control: a name nobody advertises does reach the catch-all, so the
    // assertion below can fail.
    let unknown = fixture
        .call(json!({ "name": "no_such_tool", "arguments": {} }))
        .await;
    let message = unknown["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("unknown tool"), "{unknown}");

    for tool in &TOOLS_LIST.tools {
        let response = fixture
            .call(json!({ "name": tool.name, "arguments": {} }))
            .await;
        let message = response["error"]["message"].as_str().unwrap_or_default();
        assert!(
            !message.contains("unknown tool"),
            "`{}` is advertised in tools/list but tools/call cannot dispatch it: {message}",
            tool.name,
        );
    }

    delete_audit_calls(&fixture.pool, &fixture.identity.user_sub).await;
}

/// Calls rejected before any tool runs are still accounted for: an unknown
/// tool, a missing `name`, and a known tool with malformed arguments each
/// answer JSON-RPC `invalid_params` and leave an `invalid_arguments` row
/// with no target.
#[tokio::test]
async fn rejected_calls_leave_invalid_arguments_rows() {
    let fixture = Fixture::new().await;
    let user = fixture.identity.user_sub.clone();

    let cases = [
        (json!({ "name": "drop_everything" }), "unknown"),
        (json!({ "arguments": {} }), "unknown"),
        (
            json!({ "name": "run_query", "arguments": { "server": 7 } }),
            "run_query",
        ),
    ];
    for (params, audited_tool) in cases {
        let response = fixture.call(params.clone()).await;
        assert_eq!(
            response["error"]["code"].as_i64(),
            Some(-32602),
            "{params} → {response}"
        );
        let row = latest_audit(&fixture.pool, &user, audited_tool, &params.to_string()).await;
        assert_eq!(row.outcome, "invalid_arguments", "{params}");
        assert_eq!(row.server, None);
        assert_eq!(row.database, None);
        assert_eq!(row.sql, None);
    }
    let row = latest_audit(&fixture.pool, &user, "unknown", "unknown tool").await;
    assert!(
        row.error_message
            .as_deref()
            .is_some_and(|m| m.starts_with("missing or invalid")),
        "{:?}",
        row.error_message
    );

    delete_audit_calls(&fixture.pool, &user).await;
}

/// The new introspection tools reject malformed arguments like every other
/// tool: JSON-RPC `invalid_params` plus an `invalid_arguments` row.
#[tokio::test]
async fn introspection_tools_audit_malformed_arguments() {
    let fixture = Fixture::new().await;
    let user = fixture.identity.user_sub.clone();
    let cases = [
        json!({ "name": "table_stats", "arguments": { "server": "s" } }),
        json!({ "name": "db_activity", "arguments": { "database": "d" } }),
        json!({ "name": "cancel_query", "arguments": { "server": "s", "database": "d" } }),
    ];
    for params in cases {
        let tool = params["name"].as_str().unwrap();
        let response = fixture.call(params.clone()).await;
        assert_eq!(response["error"]["code"].as_i64(), Some(-32602), "{params}");
        let row = latest_audit(&fixture.pool, &user, tool, &params.to_string()).await;
        assert_eq!(row.outcome, "invalid_arguments", "{params}");
    }
    delete_audit_calls(&fixture.pool, &user).await;
}

/// A service call whose upstream claim the transport refused (malformed
/// header, or `require_upstream` with a header missing) never reaches the
/// tool: `invalid_params` on the wire, an `invalid_arguments` row naming the
/// tool it asked for.
#[tokio::test]
async fn rejected_upstream_claim_leaves_an_invalid_arguments_row() {
    let mut fixture = Fixture::new().await;
    fixture.request.upstream = Upstream::Rejected("upstream headers required");
    let user = fixture.identity.user_sub.clone();

    let params = json!({ "name": "list_servers", "arguments": {} });
    let response = fixture.call(params.clone()).await;
    assert_eq!(
        response["error"]["code"].as_i64(),
        Some(-32602),
        "{response}"
    );
    let row = latest_audit(&fixture.pool, &user, "list_servers", "rejected upstream").await;
    assert_eq!(row.outcome, "invalid_arguments");
    assert_eq!(
        row.error_message.as_deref(),
        Some("upstream headers required")
    );
    assert_eq!(row.upstream_run_id, None);

    delete_audit_calls(&fixture.pool, &user).await;
}
