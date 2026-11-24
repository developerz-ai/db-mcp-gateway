//! Shared harness for the plan-101 O10 admin routes (explain, batch,
//! export/diff, audit stream, grant expiry): a gateway with the admin API
//! mounted, an admin bearer, seeding helpers, and cleanup of exactly the rows
//! a test made.

use std::sync::Arc;
use std::time::Duration;

use crate::common::cleanup::{
    delete_audit_calls, delete_permissions_audit, delete_permissions_user,
};
use crate::common::env::state_pool;
use crate::common::gateway::GatewayBuilder;
use db_mcp_gateway::auth::{SessionStore, jwt};
use db_mcp_gateway::state::permissions::pg::PgPermissionsRepo;
use db_mcp_gateway::state::permissions::{
    GrantAction, GrantTarget, PermissionsGrant, PermissionsSeed,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

pub const ADMIN_GROUP: &str = "o10-admins";

/// One server, two databases, a YAML group grant and a YAML user grant.
pub const YAML: &str = "servers:
  - name: prod
    kind: postgres
    host: prod.example.invalid
    role: ro
    password: hunter2
    databases: [app, billing]
permissions:
  - group: o10-eng
    grants:
      - { server: prod, database: '*', action: query_read, except: [billing],
          constraints: { row_limit: 100 } }
";

pub struct O10 {
    pub url: String,
    pub pool: PgPool,
    pub repo: Arc<PgPermissionsRepo>,
    pub sessions: SessionStore,
    signing_key: secrecy::SecretSlice<u8>,
    pub admin_sub: String,
    pub admin: String,
    subs: Vec<String>,
}

impl O10 {
    pub async fn spawn() -> Self {
        Self::spawn_with(state_pool().await).await
    }

    /// [`Self::spawn`] on a state pool the caller sized.
    pub async fn spawn_with(pool: PgPool) -> Self {
        let repo = Arc::new(PgPermissionsRepo::new(pool.clone()));
        let gw = GatewayBuilder::new(YAML)
            .admin(ADMIN_GROUP, true)
            .repo(repo.clone())
            .spawn(pool)
            .await;
        let mut h = Self {
            url: gw.url,
            pool: gw.state_db,
            repo,
            sessions: gw.sessions,
            signing_key: gw.auth_config.session_signing_key.clone(),
            admin_sub: unique("o10-admin"),
            admin: String::new(),
            subs: Vec::new(),
        };
        let sub = h.admin_sub.clone();
        h.admin = h.bearer(&sub, &[ADMIN_GROUP]).await;
        h.subs.push(sub);
        h
    }

    pub async fn bearer(&self, sub: &str, groups: &[&str]) -> String {
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        let session = self
            .sessions
            .create(
                sub,
                "o10@example.com",
                &groups,
                Duration::from_secs(600),
                None,
            )
            .await
            .expect("create session");
        jwt::issue(&self.signing_key, session.id, sub, Duration::from_secs(600)).expect("jwt")
    }

    pub fn http(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client")
    }

    pub async fn post(&self, path: &str, body: &Value) -> (reqwest::StatusCode, Value) {
        let resp = self
            .http()
            .post(format!("{}{path}", self.url))
            .bearer_auth(&self.admin)
            .json(body)
            .send()
            .await
            .expect("post");
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    pub async fn get(&self, path: &str) -> (reqwest::StatusCode, Value) {
        let resp = self
            .http()
            .get(format!("{}{path}", self.url))
            .bearer_auth(&self.admin)
            .send()
            .await
            .expect("get");
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// A tracked live user with `groups`; returns `(id, sub)`.
    pub async fn user(&mut self, prefix: &str, groups: &[&str]) -> (Uuid, String) {
        let sub = unique(prefix);
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        let user = self
            .repo
            .upsert_user(&sub, "u@example.com", &groups)
            .await
            .expect("seed user");
        self.subs.push(sub.clone());
        (user.id, sub)
    }

    pub async fn wildcard_grant(&self, user_id: Uuid, constraints: Value) -> PermissionsGrant {
        self.repo
            .create_grant(
                user_id,
                GrantTarget::Wildcard {
                    server: "prod".into(),
                },
                GrantAction::QueryRead,
                constraints,
            )
            .await
            .expect("seed grant")
    }

    /// `audit_calls` rows `tool` wrote for the admin.
    pub async fn admin_reads(&self, tool: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM audit_calls WHERE user_sub = $1 AND tool = $2")
            .bind(&self.admin_sub)
            .bind(tool)
            .fetch_one(&self.pool)
            .await
            .expect("count admin reads")
    }

    /// `permissions_audit` rows about `target_id`, oldest first.
    pub async fn audit_actions(&self, target_id: Uuid) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT action FROM permissions_audit WHERE target_id = $1 ORDER BY ts, id",
        )
        .bind(target_id)
        .fetch_all(&self.pool)
        .await
        .expect("permissions_audit rows")
    }

    pub async fn cleanup(&self) {
        for sub in &self.subs {
            let ids: Vec<Uuid> =
                sqlx::query_scalar("SELECT id FROM permissions_users WHERE user_sub = $1")
                    .bind(sub)
                    .fetch_all(&self.pool)
                    .await
                    .unwrap_or_default();
            for id in ids {
                let grants: Vec<Uuid> =
                    sqlx::query_scalar("SELECT id FROM permissions_grants WHERE user_id = $1")
                        .bind(id)
                        .fetch_all(&self.pool)
                        .await
                        .unwrap_or_default();
                for grant in grants {
                    delete_permissions_audit(&self.pool, grant).await;
                }
                let _ = sqlx::query("DELETE FROM permissions_grants WHERE user_id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await;
                delete_permissions_audit(&self.pool, id).await;
            }
            delete_permissions_user(&self.pool, sub).await;
            delete_audit_calls(&self.pool, sub).await;
        }
    }
}

pub fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

pub fn wildcard_upsert(user_id: Uuid, row_limit: u32) -> Value {
    json!({
        "op": "upsert", "user_id": user_id, "server": "prod", "db_name_wildcard": true,
        "action": "query_read", "constraints": { "row_limit": row_limit },
    })
}
