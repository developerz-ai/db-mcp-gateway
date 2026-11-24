//! The booted binary's request edge and its log lines: `Origin` validation
//! (A12), the audited client IP behind trusted proxies (A18), and the
//! dispatch span's fields on lines logged deep inside a tool call (U6).

use std::time::Duration;

use serde_json::{Value, json};

use crate::boot_binary::{BinaryGateway, service_only_yaml};
use crate::common::audit::{find_audit, latest_audit};
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;

/// How long a log line may trail the response that caused it.
const LOG_WAIT: Duration = Duration::from_secs(5);

const ORIGIN_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444443";
const PROXY_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444444";
const DIRECT_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444445";
const SPAN_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444446";

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_disallowed_origin_is_refused_before_auth_and_audit() {
    let mut gateway = BinaryGateway::spawn(
        &service_only_yaml("boot-origin", ORIGIN_TOKEN),
        &[("MCP_ALLOWED_ORIGINS", "https://agents.example.com")],
    );
    gateway.wait_listening().await;
    let pool = state_pool().await;
    delete_audit_calls(&pool, "service:boot-origin").await;

    let (status, body) = gateway
        .call_tool(
            ORIGIN_TOKEN,
            "list_servers",
            json!({}),
            &[("origin", "https://attacker.example")],
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["id"], Value::Null, "{body}");
    assert!(
        find_audit(&pool, "service:boot-origin", "list_servers")
            .await
            .is_none(),
        "a refused Origin wrote an audit row"
    );
    let refusal = gateway
        .await_record(LOG_WAIT, |line| {
            line["message"] == "rejected a request from a disallowed Origin"
                && line["reason"] == "Origin not allowed"
                && line.get("origin").is_none()
        })
        .await;
    assert!(refusal.is_some(), "{:#?}", gateway.lines());

    let (status, body) = gateway
        .call_tool(
            ORIGIN_TOKEN,
            "list_servers",
            json!({}),
            &[("origin", "https://agents.example.com")],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let row = latest_audit(
        &pool,
        "service:boot-origin",
        "list_servers",
        "listed origin",
    )
    .await;
    assert_eq!(row.outcome.as_str(), "success");

    // No Origin at all: a non-browser agent.
    let (status, body) = gateway
        .call_tool(ORIGIN_TOKEN, "list_servers", json!({}), &[])
        .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_trusted_proxy_hands_over_the_forwarded_client_ip() {
    let mut gateway = BinaryGateway::spawn(
        &service_only_yaml("boot-proxied", PROXY_TOKEN),
        &[("TRUSTED_PROXIES", "127.0.0.0/8")],
    );
    gateway.wait_listening().await;
    delete_audit_calls(&state_pool().await, "service:boot-proxied").await;

    let (status, body) = gateway
        .call_tool(
            PROXY_TOKEN,
            "list_servers",
            json!({}),
            &[("x-forwarded-for", "198.51.100.9, 203.0.113.7")],
        )
        .await;

    assert_eq!(status, 200, "{body}");
    let row = latest_audit(
        &state_pool().await,
        "service:boot-proxied",
        "list_servers",
        "proxied call",
    )
    .await;
    assert_eq!(row.ip.as_deref(), Some("203.0.113.7"));
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn an_untrusted_peer_cannot_forge_its_ip() {
    let mut gateway = BinaryGateway::spawn(&service_only_yaml("boot-direct", DIRECT_TOKEN), &[]);
    gateway.wait_listening().await;
    delete_audit_calls(&state_pool().await, "service:boot-direct").await;

    let (status, body) = gateway
        .call_tool(
            DIRECT_TOKEN,
            "list_servers",
            json!({}),
            &[("x-forwarded-for", "203.0.113.7")],
        )
        .await;

    assert_eq!(status, 200, "{body}");
    let row = latest_audit(
        &state_pool().await,
        "service:boot-direct",
        "list_servers",
        "direct call",
    )
    .await;
    assert_eq!(row.ip.as_deref(), Some("127.0.0.1"));
}

/// A target nobody can resolve: the tool fails at connect, inside the exec
/// layer, on a line that names no request itself.
const SPAN_YAML: &str = "servers:
  - name: unreachable
    kind: postgres
    host: target.example.invalid
    tls: insecure
    databases:
      - { name: app, role: ro, password: unreachable-dev-only }
permissions:
  - group: svc-boot-span
    grants:
      - { server: unreachable, database: app, action: query_read }
service_accounts:
  - name: boot-span
    group: svc-boot-span
    token: dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444446
";

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_target_error_line_carries_the_dispatch_span() {
    let mut gateway = BinaryGateway::spawn(SPAN_YAML, &[]);
    gateway.wait_listening().await;
    delete_audit_calls(&state_pool().await, "service:boot-span").await;

    let (status, body) = gateway
        .call_tool(
            SPAN_TOKEN,
            "run_query",
            json!({ "server": "unreachable", "database": "app", "sql": "SELECT 1" }),
            &[],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    let row = latest_audit(
        &state_pool().await,
        "service:boot-span",
        "run_query",
        "unreachable target",
    )
    .await;

    let exec_line = gateway
        .await_record(LOG_WAIT, |line| {
            line["target"]
                .as_str()
                .is_some_and(|target| target.starts_with("db_mcp_gateway::exec"))
                && line.get("request_id").is_none()
        })
        .await;
    let Some(line) = exec_line else {
        panic!("no exec-layer line:\n{:#?}", gateway.lines());
    };
    assert_eq!(line["span"]["name"], "tool_dispatch", "{line}");
    assert_eq!(line["span"]["request_id"], row.request_id, "{line}");
    assert_eq!(line["span"]["tool"], "run_query", "{line}");
    assert_eq!(line["span"]["server"], "unreachable", "{line}");
    assert_eq!(line["span"]["db"], "app", "{line}");
}
