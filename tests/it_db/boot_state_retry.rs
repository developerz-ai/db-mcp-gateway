//! U7: boot retries the state DB within `STATE_DB_CONNECT_TIMEOUT_SECONDS`
//! instead of exiting on the first failed attempt — and a failed bring-up
//! never prints the DSN's password (MUST #1).

use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use crate::boot_binary::{BinaryGateway, free_port, service_only_yaml};
use crate::common::env::state_db_url;

const TOKEN: &str = "dbmcp_svc_4444444444444444444444444444444444444444444444444444444444444442";
const SECRET: &str = "hunter2-boot-secret";
const RETRYING: &str = "state DB not reachable yet; retrying";

/// `state_db_url()` re-pointed at `127.0.0.1:port`, password optionally
/// swapped.
fn state_url_via(port: u16, password: Option<&str>) -> (String, String) {
    let real = url::Url::parse(&state_db_url()).expect("state DB url");
    let upstream = format!(
        "{}:{}",
        real.host_str().expect("host"),
        real.port().unwrap_or(5432)
    );
    let mut via = real.clone();
    via.set_host(Some("127.0.0.1")).expect("host");
    via.set_port(Some(port)).expect("port");
    if let Some(password) = password {
        via.set_password(Some(password)).expect("password");
    }
    (via.to_string(), upstream)
}

/// Forward every connection on `port` to `upstream`, starting after `delay`.
fn spawn_late_proxy(port: u16, upstream: String, delay: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind proxy port");
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            let upstream = upstream.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(&upstream).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::parallel(world)]
async fn boot_waits_for_a_state_db_that_comes_up_late() {
    let port = free_port();
    let (url, upstream) = state_url_via(port, None);
    // Past the 5 s pool acquire timeout: sqlx itself retries a refused
    // connect until then, so a shorter delay never reaches boot's retry.
    spawn_late_proxy(port, upstream, Duration::from_secs(8));

    let mut gateway = BinaryGateway::spawn(
        &service_only_yaml("boot-late-db", TOKEN),
        &[
            ("STATE_DB_URL", &url),
            ("STATE_DB_CONNECT_TIMEOUT_SECONDS", "60"),
        ],
    );
    gateway.wait_listening().await;

    assert!(
        gateway.lines().iter().any(|line| line.contains(RETRYING)),
        "no retry before the DB came up:\n{:#?}",
        gateway.lines()
    );
    let ready = reqwest::get(format!("{}/readyz", gateway.base_url))
        .await
        .expect("readyz answers");
    assert_eq!(ready.status(), 200);
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn boot_gives_up_after_the_budget_without_printing_the_password() {
    let (url, _) = state_url_via(free_port(), Some(SECRET));
    let mut gateway = BinaryGateway::spawn(
        &service_only_yaml("boot-no-db", TOKEN),
        &[
            ("STATE_DB_URL", &url),
            ("STATE_DB_CONNECT_TIMEOUT_SECONDS", "6"),
        ],
    );

    let status = gateway.wait_exit(Duration::from_secs(45)).await;

    assert!(!status.success());
    let lines = gateway.lines();
    assert!(
        lines.iter().any(|line| line.contains(RETRYING)),
        "{lines:#?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("DSN withheld")),
        "{lines:#?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains(SECRET)),
        "password leaked:\n{lines:#?}"
    );
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_malformed_retry_budget_fails_boot() {
    let mut gateway = BinaryGateway::spawn(
        &service_only_yaml("boot-bad-budget", TOKEN),
        &[("STATE_DB_CONNECT_TIMEOUT_SECONDS", "soon")],
    );

    let status = gateway.wait_exit(Duration::from_secs(30)).await;

    assert!(!status.success());
    assert!(
        gateway
            .lines()
            .iter()
            .any(|line| line.contains("invalid STATE_DB_CONNECT_TIMEOUT_SECONDS `soon`")),
        "{:#?}",
        gateway.lines()
    );
}
