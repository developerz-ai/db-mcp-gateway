//! `kind: redis` through the real MCP surface: a gateway booted on YAML,
//! mock-OIDC login, `tools/call` over HTTP — against Redis AND Dragonfly.
//! Every call asserts its audit row (`db_type: redis`, the argv as `sql`).

use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::gateway::{LoggedInGateway, spawn_logged_in};
use crate::common::idp::MockUser;
use crate::common::redis_target::{
    DB_INDEX, Flavor, READ_PASSWORD, READ_USER, admin, admin_cmd, delete_keys, ensure_read_user,
    unique_key,
};
use serde_json::{Value, json};

fn yaml() -> String {
    let servers: String = Flavor::ALL
        .iter()
        .map(|flavor| {
            format!(
                "  - name: {name}\n    kind: redis\n    host: localhost\n    port: {port}\n    \
                 tls: insecure\n    databases:\n      - name: \"{DB_INDEX}\"\n        \
                 role: {READ_USER}\n        password: {READ_PASSWORD}\n",
                name = flavor.name(),
                port = flavor.port(),
            )
        })
        .collect();
    format!(
        "servers:\n{servers}\npermissions:\n  - group: cache-readers\n    grants:\n      \
         - {{ server: \"*\", database: \"*\", action: query_read }}\n      \
         - {{ server: \"*\", database: \"*\", action: schema_read }}\n"
    )
}

struct Fixture {
    gw: LoggedInGateway,
}

impl Fixture {
    async fn new() -> Self {
        for flavor in Flavor::ALL {
            ensure_read_user(flavor).await;
        }
        let user = MockUser {
            sub: format!("redis-e2e-{}", uuid::Uuid::new_v4().simple()),
            email: "redis-e2e@example.com".into(),
            groups: vec!["cache-readers".into()],
        };
        Self {
            gw: spawn_logged_in(&yaml(), user).await,
        }
    }

    async fn call(&self, tool: &str, arguments: Value) -> Value {
        reqwest::Client::new()
            .post(format!("{}/mcp", self.gw.url))
            .bearer_auth(&self.gw.bearer)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": arguments }
            }))
            .send()
            .await
            .expect("gateway reachable")
            .json()
            .await
            .expect("JSON-RPC body")
    }

    async fn latest(&self, tool: &str, label: &str) -> db_mcp_gateway::audit::AuditRow {
        latest_audit(&self.gw.state_db, &self.gw.user_sub, tool, label).await
    }

    async fn finish(self) {
        delete_audit_calls(&self.gw.state_db, &self.gw.user_sub).await;
    }
}

fn tool_payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("text content: {response}"));
    serde_json::from_str(text).expect("payload is JSON")
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn run_query_reads_a_hash_and_audits_it_as_redis() {
    let f = Fixture::new().await;
    for flavor in Flavor::ALL {
        let mut side = admin(flavor).await;
        let h = unique_key("e2e");
        admin_cmd(&mut side, &["HSET", &h, "plan", "pro"]).await;
        let argv = format!(r#"["HGETALL","{h}"]"#);
        let resp = f
            .call(
                "run_query",
                json!({ "server": flavor.name(), "database": DB_INDEX, "sql": argv }),
            )
            .await;
        delete_keys(&mut side, &[&h]).await;

        assert_ne!(resp["result"]["isError"], true, "{resp}");
        let payload = tool_payload(&resp);
        assert_eq!(payload["columns"], json!(["field", "value"]), "{resp}");
        assert_eq!(payload["rows"], json!([["plan", "pro"]]), "{resp}");
        assert_eq!(payload["truncated"], false);

        let row = f.latest("run_query", "redis run_query").await;
        assert_eq!(row.outcome, "success", "{}", flavor.name());
        assert_eq!(row.db_type.as_deref(), Some("redis"));
        assert_eq!(row.server.as_deref(), Some(flavor.name()));
        assert_eq!(row.database.as_deref(), Some(DB_INDEX));
        assert_eq!(row.sql.as_deref(), Some(argv.as_str()));
        assert_eq!(row.row_count, Some(1));
    }
    f.finish().await;
}

/// A write is refused at the tool edge (`forbidden_sql`), audited, and
/// never reaches the server.
#[tokio::test]
#[serial_test::parallel(world)]
async fn run_query_refuses_a_write_and_audits_forbidden_sql() {
    let f = Fixture::new().await;
    for flavor in Flavor::ALL {
        let k = unique_key("e2e-set");
        let argv = format!(r#"["set","{k}","v"]"#);
        let resp = f
            .call(
                "run_query",
                json!({ "server": flavor.name(), "database": DB_INDEX, "sql": argv }),
            )
            .await;
        assert_eq!(resp["result"]["isError"], true, "{resp}");
        assert_eq!(tool_payload(&resp)["code"], "forbidden_sql", "{resp}");

        let row = f.latest("run_query", "redis SET").await;
        assert_eq!(row.outcome, "forbidden_sql", "{}", flavor.name());
        assert_eq!(row.db_type.as_deref(), Some("redis"));
        let mut side = admin(flavor).await;
        assert_eq!(
            admin_cmd(&mut side, &["EXISTS", &k]).await,
            redis::Value::Int(0)
        );
    }
    f.finish().await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn run_query_answers_a_malformed_argv_with_invalid_arguments() {
    let f = Fixture::new().await;
    let resp = f
        .call(
            "run_query",
            json!({ "server": "redis", "database": DB_INDEX, "sql": "GET some:key" }),
        )
        .await;
    assert_eq!(resp["error"]["code"], -32602, "{resp}");
    let row = f.latest("run_query", "redis malformed").await;
    assert_eq!(row.outcome, "invalid_arguments");
    f.finish().await;
}

/// `describe_schema` and `explain` have no Redis meaning: a stable
/// `unsupported_backend`, audited.
#[tokio::test]
#[serial_test::parallel(world)]
async fn describe_schema_and_explain_are_unsupported_backend() {
    let f = Fixture::new().await;
    for flavor in Flavor::ALL {
        for (tool, arguments) in [
            (
                "describe_schema",
                json!({ "server": flavor.name(), "database": DB_INDEX }),
            ),
            (
                "explain",
                json!({ "server": flavor.name(), "database": DB_INDEX, "sql": r#"["GET","k"]"# }),
            ),
        ] {
            let resp = f.call(tool, arguments).await;
            assert_eq!(resp["result"]["isError"], true, "{tool}: {resp}");
            assert_eq!(
                tool_payload(&resp)["code"],
                "unsupported_backend",
                "{tool}: {resp}"
            );
            let row = f.latest(tool, tool).await;
            assert_eq!(row.outcome, "unsupported_backend", "{tool}");
            assert_eq!(row.db_type.as_deref(), Some("redis"), "{tool}");
        }
    }
    f.finish().await;
}
