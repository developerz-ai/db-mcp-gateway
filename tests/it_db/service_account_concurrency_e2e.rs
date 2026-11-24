//! Per-service-account concurrency cap through the real router (plan 101
//! slice 12 step 3, spec 14): `service_accounts[].max_concurrent_requests`
//! replaces the per-identity default for that token in both directions — a
//! fleet may run more than the default, a tight account fewer — and one
//! account at its cap never sheds another identity.
//!
//! A request is held in flight by sending its headers and stalling its body:
//! the limiter takes its permits before the handler reads the body, and the
//! 10 s body deadline releases them if the test dies.
//!
//! State DB only — `list_servers` reaches no target database.

use std::time::Duration;

use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use crate::common::gateway::{GatewayBuilder, TestGateway};
use db_mcp_gateway::config::Config;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use uuid::Uuid;

const TIGHT_TOKEN: &str =
    "dbmcp_svc_5555555555555555555555555555555555555555555555555555555555555555";
const FLEET_TOKEN: &str =
    "dbmcp_svc_6666666666666666666666666666666666666666666666666666666666666666";
const TIGHT_CAP: usize = 2;

/// The per-identity cap a caller without its own gets.
fn default_cap() -> usize {
    Config::default().max_concurrent_per_identity
}

/// Above the default, so admitting it proves the account cap replaced the
/// default rather than only lowering it.
fn fleet_cap() -> usize {
    default_cap() + 4
}

fn yaml(account: &str) -> String {
    let fleet_cap = fleet_cap();
    format!(
        r#"
servers:
  - name: staging
    kind: postgres
    description: E2E staging
    host: staging.example.invalid
    databases:
      - {{ name: app, role: ro, password: stagingpw }}

permissions:
  - group: svc-agents
    grants:
      - {{ server: staging, database: app, action: query_read }}

service_accounts:
  - name: {account}-tight
    group: svc-agents
    token: {TIGHT_TOKEN}
    max_concurrent_requests: {TIGHT_CAP}
  - name: {account}-fleet
    group: svc-agents
    token: {FLEET_TOKEN}
    max_concurrent_requests: {fleet_cap}
"#
    )
}

async fn boot() -> (TestGateway, String) {
    let account = format!("cap-{}", Uuid::new_v4().simple());
    let gw = GatewayBuilder::new(&yaml(&account))
        .spawn(state_pool().await)
        .await;
    (gw, account)
}

/// Open `count` `/mcp` requests whose bodies never finish arriving. Dropping
/// the returned streams ends them.
async fn stall(gw: &TestGateway, token: &str, count: usize) -> Vec<TcpStream> {
    let addr = gw.url.trim_start_matches("http://");
    let head = format!(
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n{{"
    );
    let mut streams = Vec::with_capacity(count);
    for _ in 0..count {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(head.as_bytes()).await.expect("send head");
        streams.push(stream);
    }
    streams
}

/// Poll until `token`'s account (cap `cap`) has exactly `held` requests in
/// flight, read off a probe's own admission: a 429 once the cap is full,
/// else the `x-dbmcp-concurrency-remaining` it was admitted with.
async fn await_in_flight(gw: &TestGateway, token: &str, cap: usize, held: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let probe = list_servers(gw, token).await;
        let remaining = probe
            .headers()
            .get("x-dbmcp-concurrency-remaining")
            .and_then(|v| v.to_str().ok()?.parse::<usize>().ok());
        let settled = if held >= cap {
            probe.status() == StatusCode::TOO_MANY_REQUESTS
        } else {
            probe.status() == StatusCode::OK && remaining == Some(cap - held - 1)
        };
        if settled {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{held} of {cap} never in flight (last: {} remaining {remaining:?})",
            probe.status()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn list_servers(gw: &TestGateway, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/mcp", gw.url))
        .bearer_auth(token)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "list_servers", "arguments": {} }
        }))
        .send()
        .await
        .expect("request sent")
}

async fn assert_shed(response: reqwest::Response, label: &str) {
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, "{label}");
    let body: Value = response.json().await.expect("429 body is JSON");
    assert_eq!(
        body["error"]["data"]["code"], "concurrency_limit_exceeded",
        "{label}: {body}"
    );
}

async fn assert_admitted(gw: &TestGateway, token: &str, subject: &str, label: &str) {
    let response = list_servers(gw, token).await;
    assert_eq!(response.status(), StatusCode::OK, "{label}");
    let body: Value = response.json().await.expect("JSON-RPC body");
    assert_eq!(body["result"]["isError"], false, "{label}: {body}");
    let row = latest_audit(&gw.state_db, subject, "list_servers", label).await;
    assert_eq!(row.outcome, "success", "{label}");
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn account_cap_below_the_default_sheds_only_that_account() {
    let (gw, account) = boot().await;
    let tight = format!("service:{account}-tight");
    let fleet = format!("service:{account}-fleet");

    let held = stall(&gw, TIGHT_TOKEN, TIGHT_CAP).await;
    await_in_flight(&gw, TIGHT_TOKEN, TIGHT_CAP, TIGHT_CAP).await;
    assert_shed(
        list_servers(&gw, TIGHT_TOKEN).await,
        "tight account at its cap",
    )
    .await;
    assert_admitted(
        &gw,
        FLEET_TOKEN,
        &fleet,
        "other account while tight is full",
    )
    .await;

    drop(held);
    await_in_flight(&gw, TIGHT_TOKEN, TIGHT_CAP, 0).await;
    assert_admitted(&gw, TIGHT_TOKEN, &tight, "tight account after release").await;

    delete_audit_calls(&gw.state_db, &tight).await;
    delete_audit_calls(&gw.state_db, &fleet).await;
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn account_cap_above_the_default_admits_past_it() {
    let (gw, account) = boot().await;
    let fleet = format!("service:{account}-fleet");

    let mut held = stall(&gw, FLEET_TOKEN, default_cap()).await;
    await_in_flight(&gw, FLEET_TOKEN, fleet_cap(), default_cap()).await;
    assert_admitted(&gw, FLEET_TOKEN, &fleet, "fleet past the default cap").await;

    held.extend(stall(&gw, FLEET_TOKEN, fleet_cap() - default_cap()).await);
    await_in_flight(&gw, FLEET_TOKEN, fleet_cap(), fleet_cap()).await;
    assert_shed(list_servers(&gw, FLEET_TOKEN).await, "fleet at its own cap").await;

    drop(held);
    delete_audit_calls(&gw.state_db, &fleet).await;
}
