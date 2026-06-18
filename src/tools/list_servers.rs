//! `list_servers` — the caller's visible servers, sans connection info.
//!
//! Per spec 03: returns logical name, kind, and human description. No host,
//! port, role, password, or database listing. The output goes through a
//! `Serialize`-able view type that doesn't even have a `password` field —
//! leaking credentials is structurally impossible, not "remembered to strip".
//!
//! Audits every dispatch through `audit_dispatch` (spec 07: "every tool call
//! writes one row"). The audit row has `server`/`database`/`sql` all `None`
//! because `list_servers` doesn't address a target.

use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, PermissionsCache, cache::load_or_empty};
use crate::config::{ConfigFile, Grant, ServerKind};
use crate::transport::jsonrpc::Response;

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, error_outcome, success_outcome,
};

const TOOL_NAME: &str = "list_servers";

/// Credential-free server view returned over the wire.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SafeServerView {
    pub name: String,
    pub kind: &'static str,
    pub description: String,
}

#[derive(Debug, Serialize)]
struct ListServersResult {
    servers: Vec<SafeServerView>,
}

pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    permissions_cache: Option<&PermissionsCache>,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    _arguments: Option<Value>,
) -> Response {
    let header = AuditHeader {
        tool: TOOL_NAME,
        server: None,
        database: None,
        sql: None,
        reason: None,
        db_type: None,
    };
    let db_grants = match load_or_empty(permissions_cache, identity).await {
        Ok(g) => g,
        Err(err) => {
            tracing::error!(%err, "permissions cache load failed");
            let resp = error_outcome(id.clone(), "internal", "permissions_cache_load_failed");
            let work = async move { resp };
            return audit_dispatch(id, identity, state_db, request_ctx, header, work).await;
        }
    };
    let work_id = id.clone();
    let work = async move { compute_outcome(work_id, identity, config, &db_grants) };
    audit_dispatch(id, identity, state_db, request_ctx, header, work).await
}

fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
) -> Outcome {
    let servers: Vec<SafeServerView> = config
        .servers
        .iter()
        .filter(|s| authz::can_see_server_effective(identity, s, &config.permissions, db_grants))
        .map(SafeServerView::from)
        .collect();
    let row_count = i64::try_from(servers.len()).unwrap_or(i64::MAX);

    let payload = match serde_json::to_string(&ListServersResult { servers }) {
        Ok(t) => t,
        Err(_) => {
            // Serialization of our safe-view types is infallible in practice,
            // but `expect` on the request path is banned (CLAUDE.md): degrade
            // to a typed internal error instead of panicking.
            return error_outcome(id, "internal", "tool.list_servers.serialization_failed");
        }
    };

    success_outcome(id, payload, None, Some(row_count), Some(false))
}

impl From<&crate::config::Server> for SafeServerView {
    fn from(server: &crate::config::Server) -> Self {
        Self {
            name: server.name.clone(),
            kind: kind_label(server.kind),
            description: server.description.clone(),
        }
    }
}

fn kind_label(kind: ServerKind) -> &'static str {
    super::db_type_label(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SessionId;
    use crate::config::ConfigFile;

    fn identity(groups: &[&str]) -> Identity {
        Identity {
            session_id: SessionId::new(),
            user_sub: "u".to_string(),
            user_email: "u@example.com".to_string(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    const YAML: &str = r#"
servers:
  - name: prod
    kind: postgres
    description: Customer-facing prod
    host: prod.db.internal
    databases:
      - { name: app, role: ro, password: hunter2 }
  - name: staging
    kind: postgres
    description: Staging
    host: staging.db.internal
    databases:
      - { name: app, role: ro, password: stagingpw }
  - name: analytics
    kind: mysql
    description: Analytics
    host: an.db.internal
    databases:
      - { name: warehouse, role: ro, password: dwpw }

permissions:
  - group: backend-engineers
    grants:
      - { server: staging, database: "*", action: query_read }
      - { server: prod,    database: "*", action: schema_read }
  - group: analytics-team
    grants:
      - { server: analytics, database: "*", action: query_read }
"#;

    fn load() -> ConfigFile {
        ConfigFile::from_yaml_str(YAML).expect("yaml parses")
    }

    /// Drives the sync `compute_outcome` directly. Unit-testing the filter +
    /// shape logic doesn't need the audit chokepoint (covered by integration
    /// tests against a real state DB).
    fn body_for(groups: &[&str]) -> String {
        let outcome = compute_outcome(Value::from(1), &identity(groups), &load(), &[]);
        let json = serde_json::to_value(&outcome.response).unwrap();
        json["result"]["content"][0]["text"]
            .as_str()
            .expect("content[0].text is the JSON-stringified payload")
            .to_string()
    }

    #[test]
    fn engineer_sees_prod_and_staging_but_not_analytics() {
        let body = body_for(&["backend-engineers"]);
        assert!(body.contains("\"name\":\"prod\""), "{body}");
        assert!(body.contains("\"name\":\"staging\""), "{body}");
        assert!(!body.contains("\"name\":\"analytics\""), "{body}");
    }

    #[test]
    fn analyst_only_sees_analytics() {
        let body = body_for(&["analytics-team"]);
        assert!(body.contains("\"name\":\"analytics\""), "{body}");
        assert!(!body.contains("\"name\":\"prod\""), "{body}");
        assert!(!body.contains("\"name\":\"staging\""), "{body}");
    }

    #[test]
    fn user_in_no_group_sees_nothing() {
        let body = body_for(&[]);
        assert!(body.contains("\"servers\":[]"), "{body}");
    }

    /// row_count in Outcome equals the visible server count — operators
    /// reading audit_calls.row_count get the same answer.
    #[test]
    fn row_count_matches_visible_servers() {
        let outcome = compute_outcome(
            Value::from(1),
            &identity(&["backend-engineers"]),
            &load(),
            &[],
        );
        assert_eq!(outcome.code, "success");
        assert_eq!(outcome.row_count, Some(2));
        assert_eq!(outcome.truncated, Some(false));
    }

    /// The hard one: no inline password value (literal, env-ref, or vault-ref)
    /// can ever appear in the tool output. Hunter2 is in the YAML; it must
    /// never reach the wire.
    #[test]
    fn no_password_ever_appears_in_output() {
        for groups in [
            vec!["backend-engineers"],
            vec!["analytics-team"],
            vec!["backend-engineers", "analytics-team"],
        ] {
            let body = body_for(&groups);
            assert!(!body.contains("hunter2"), "leaked literal password: {body}");
            assert!(
                !body.contains("stagingpw"),
                "leaked literal password: {body}"
            );
            assert!(!body.contains("dwpw"), "leaked literal password: {body}");
            assert!(!body.contains("password"), "field name leaked: {body}");
            assert!(!body.contains("role"), "role name leaked: {body}");
            assert!(!body.contains("host"), "host leaked: {body}");
        }
    }
}
