//! `list_databases` — for a given server, list databases the caller is
//! permitted to see. Per spec doc 03: returns logical name + description, no
//! connection info. No DB hit; pure config + authz.
//!
//! Server-existence non-leak: if the caller has no grants on ANY database of
//! the requested server, we return `forbidden` — never an empty list. An
//! empty list would tell the caller "the server exists, you just can't see
//! any of its databases", which is itself a leak.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Identity;
use crate::authz::{self, Decision, PermissionsCache, cache::load_or_empty};
use crate::config::{Action, ConfigFile, Database, Grant};
use crate::transport::jsonrpc::{ErrorObject, Response};

use super::audit_dispatch::{
    AuditHeader, Outcome, RequestContext, audit_dispatch, error_outcome, success_outcome,
};

const TOOL_NAME: &str = "list_databases";

#[derive(Debug, Deserialize)]
pub struct Arguments {
    pub server: String,
}

/// Credential-free database view returned over the wire. Mirrors
/// `tools::list_servers::SafeServerView` — no role, no password, no DSN.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct SafeDatabaseView {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
struct ListDatabasesResult {
    databases: Vec<SafeDatabaseView>,
}

pub async fn run(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    permissions_cache: Option<&PermissionsCache>,
    state_db: Option<&PgPool>,
    request_ctx: &RequestContext,
    arguments: Option<Value>,
) -> Response {
    let args: Arguments = match arguments.map(serde_json::from_value::<Arguments>) {
        Some(Ok(a)) => a,
        _ => {
            return Response::error(
                id,
                ErrorObject::invalid_params("list_databases requires `server`"),
            );
        }
    };

    let header = AuditHeader {
        tool: TOOL_NAME,
        server: Some(&args.server),
        database: None,
        sql: None,
        reason: None,
        db_type: super::db_type_for_server(config, &args.server),
    };
    let db_grants = match load_or_empty(permissions_cache, identity).await {
        Ok(g) => g,
        Err(err) => {
            tracing::error!(%err, "permissions cache load failed");
            let resp = error_outcome(id.clone(), "internal", "permissions_cache_load_failed");
            let work = async move { resp };
            return audit_dispatch(
                id,
                identity,
                state_db,
                request_ctx,
                header,
                &config.logging.stream,
                work,
            )
            .await;
        }
    };
    let work = compute_outcome(id.clone(), identity, config, &db_grants, &args);
    audit_dispatch(
        id,
        identity,
        state_db,
        request_ctx,
        header,
        &config.logging.stream,
        work,
    )
    .await
}

async fn compute_outcome(
    id: Value,
    identity: &Identity,
    config: &ConfigFile,
    db_grants: &[Grant],
    args: &Arguments,
) -> Outcome {
    let Some(server) = config.servers.iter().find(|s| s.name == args.server) else {
        return error_outcome(id, "forbidden", "no grants for this server");
    };

    let visible: Vec<&Database> = server
        .databases
        .iter()
        .filter(|db| {
            matches!(
                authz::evaluate_effective(
                    identity,
                    Action::SchemaRead,
                    &server.name,
                    &db.name,
                    &config.permissions,
                    db_grants,
                ),
                Decision::Allow { .. }
            )
        })
        .collect();

    if visible.is_empty() {
        return error_outcome(id, "forbidden", "no grants for this server");
    }

    let row_count = i64::try_from(visible.len()).unwrap_or(i64::MAX);
    let view: Vec<SafeDatabaseView> = visible
        .into_iter()
        .map(|db| SafeDatabaseView {
            name: db.name.clone(),
            description: db.description.clone(),
        })
        .collect();
    let payload = ListDatabasesResult { databases: view };
    let text = match serde_json::to_string(&payload) {
        Ok(t) => t,
        Err(_) => return error_outcome(id, "internal", "failed to serialize result"),
    };

    success_outcome(id, text, None, Some(row_count), Some(false))
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
            issued_at: chrono::Utc::now(),
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
      - { name: billing, role: ro, password: billing_pw }
      - { name: analytics, role: ro, password: analytics_pw }

permissions:
  - group: engineers
    grants:
      - { server: prod, database: app, action: schema_read }
  - group: analytics-team
    grants:
      - { server: prod, database: analytics, action: query_read }
  - group: ops
    grants:
      - { server: prod, database: "*", action: schema_read }
"#;

    fn load() -> ConfigFile {
        ConfigFile::from_yaml_str(YAML).expect("yaml parses")
    }

    async fn compute_for(groups: &[&str], server: &str) -> Outcome {
        let args = Arguments {
            server: server.to_string(),
        };
        compute_outcome(Value::from(1), &identity(groups), &load(), &[], &args).await
    }

    fn payload(outcome: &Outcome) -> Value {
        let value = serde_json::to_value(&outcome.response).unwrap();
        let text = value["result"]["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap()
    }

    #[tokio::test]
    async fn engineer_sees_only_app() {
        let outcome = compute_for(&["engineers"], "prod").await;
        assert_eq!(outcome.code, "success");
        let body = payload(&outcome);
        let names: Vec<&str> = body["databases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["app"]);
    }

    #[tokio::test]
    async fn analyst_sees_only_analytics() {
        let outcome = compute_for(&["analytics-team"], "prod").await;
        assert_eq!(outcome.code, "success");
        let body = payload(&outcome);
        let names: Vec<&str> = body["databases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["analytics"]);
    }

    #[tokio::test]
    async fn ops_with_wildcard_sees_all() {
        let outcome = compute_for(&["ops"], "prod").await;
        assert_eq!(outcome.code, "success");
        let body = payload(&outcome);
        let names: Vec<&str> = body["databases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["app", "billing", "analytics"]);
    }

    /// User with no matching grants on the requested server must not learn
    /// the server exists — return `forbidden`, not an empty list.
    #[tokio::test]
    async fn user_with_no_grants_gets_forbidden_not_empty() {
        let outcome = compute_for(&["finance"], "prod").await;
        assert_eq!(outcome.code, "forbidden");
        let body = payload(&outcome);
        assert_eq!(body["code"], "forbidden");
    }

    /// Server doesn't exist → same `forbidden` as no-grants, identical
    /// message. Caller cannot probe for server names.
    #[tokio::test]
    async fn unknown_server_is_forbidden_with_same_message() {
        let outcome = compute_for(&["engineers"], "nonexistent").await;
        assert_eq!(outcome.code, "forbidden");
        let body = payload(&outcome);
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["message"], "no grants for this server");
    }

    /// No password substring ever appears in the tool output, regardless of
    /// which group the caller is in. Mirrors the `list_servers` guard.
    #[tokio::test]
    async fn no_password_in_output() {
        for groups in [vec!["engineers"], vec!["analytics-team"], vec!["ops"]] {
            let outcome = compute_for(&groups, "prod").await;
            let body = serde_json::to_string(&payload(&outcome)).unwrap();
            assert!(!body.contains("hunter2"), "leak: {body}");
            assert!(!body.contains("billing_pw"), "leak: {body}");
            assert!(!body.contains("analytics_pw"), "leak: {body}");
            assert!(!body.contains("password"), "field leak: {body}");
            assert!(!body.contains("role"), "field leak: {body}");
            assert!(!body.contains("host"), "field leak: {body}");
        }
    }
}
