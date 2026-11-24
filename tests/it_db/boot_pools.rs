//! U4: the permissions listener runs on its own pool, so a one-connection
//! request pool still serves while it holds its `LISTEN` connection.

use std::time::Duration;

use crate::boot_binary::{BinaryGateway, service_only_yaml};
use crate::common::audit::latest_audit;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;

const TOKEN: &str = "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444441";

#[tokio::test]
#[serial_test::parallel(world)]
async fn one_connection_request_pool_serves_beside_the_listener() {
    let mut gateway = BinaryGateway::spawn(
        &service_only_yaml("boot-pool-one", TOKEN),
        &[("STATE_DB_POOL_SIZE", "1")],
    );
    gateway.wait_listening().await;
    delete_audit_calls(&state_pool().await, "service:boot-pool-one").await;
    // The listener subscribes right after boot; give it time to hold its
    // connection, which used to be the request pool's only one.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (status, body) = gateway
        .call_tool(TOKEN, "list_servers", serde_json::json!({}), &[])
        .await;

    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    let row = latest_audit(
        &state_pool().await,
        "service:boot-pool-one",
        "list_servers",
        "pool-size-1 list_servers",
    )
    .await;
    assert_eq!(row.outcome.as_str(), "success");
}

const YAML_ONLY_TOKEN: &str =
    "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444447";

/// A2: `driver: none` boots with no permissions store and no listener, and
/// still serves YAML grants.
#[tokio::test]
#[serial_test::parallel(world)]
async fn yaml_only_mode_starts_no_store_or_listener() {
    let yaml = format!(
        "{}permissions_store:\n  driver: none\n",
        service_only_yaml("boot-yaml-only", YAML_ONLY_TOKEN)
    );
    let mut gateway = BinaryGateway::spawn(&yaml, &[]);
    gateway.wait_listening().await;
    delete_audit_calls(&state_pool().await, "service:boot-yaml-only").await;

    let (status, body) = gateway
        .call_tool(YAML_ONLY_TOKEN, "list_servers", serde_json::json!({}), &[])
        .await;

    assert_eq!(status, 200, "{body}");
    let row = latest_audit(
        &state_pool().await,
        "service:boot-yaml-only",
        "list_servers",
        "yaml-only list_servers",
    )
    .await;
    assert_eq!(row.outcome.as_str(), "success");
    let lines = gateway.lines();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("YAML-only grants, no store or listener")),
        "{lines:#?}"
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("permissions listener")),
        "{lines:#?}"
    );
}
