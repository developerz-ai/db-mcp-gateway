//! `--healthcheck` against the real binary, booted on the dev state DB: the
//! probe a distroless image's container healthcheck runs.

use std::process::Command;

use crate::boot_binary::BinaryGateway;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::parallel(world)]
async fn healthcheck_passes_against_a_booted_gateway() {
    let mut gateway = BinaryGateway::spawn("servers: []\npermissions: []\n", &[]);
    gateway.wait_listening().await;
    let bind = gateway
        .base_url
        .strip_prefix("http://")
        .expect("plain-HTTP harness")
        .to_string();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_db-mcp-gateway"))
            .arg("--healthcheck")
            .env_clear()
            .env("GATEWAY_BIND", bind)
            .env("TLS_DISABLED", "true")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(stdout.starts_with("healthy:"), "{stdout}");
}
