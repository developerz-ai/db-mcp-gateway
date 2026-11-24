//! Senders that dribble their request body must not pin the unauthenticated
//! OAuth budget: bodies are read before a concurrency permit is taken, so a
//! token request still gets through while slow bodies are in flight, and a
//! body that never completes is answered `408` without ever holding a permit.
//! `/mcp` keeps its own budget throughout.

use std::time::Duration;

use crate::common::gateway::{SERVICE_TOKEN, SERVICE_YAML, spawn_offline};
use db_mcp_gateway::config::Config;
use reqwest::StatusCode;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 8 / 8 → an OAuth budget of one permit, so a single held permit sheds.
const GATED_CAP: usize = 8;
const SLOW_SENDERS: usize = 4;

/// Open a `/token` request whose declared body never fully arrives: one byte
/// every 200 ms. Returns the stream so the caller can read the verdict.
async fn slow_sender(addr: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let head = format!(
        "POST /token HTTP/1.1\r\nHost: {addr}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 4096\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.expect("head");
    stream
}

async fn dribble(mut stream: TcpStream) -> String {
    let mut verdict = Vec::new();
    loop {
        tokio::select! {
            read = stream.read_buf(&mut verdict) => {
                if read.unwrap_or(0) == 0 || verdict.windows(4).any(|w| w == b"\r\n\r\n") {
                    return String::from_utf8_lossy(&verdict).into_owned();
                }
            }
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                if stream.write_all(b"g").await.is_err() {
                    return String::from_utf8_lossy(&verdict).into_owned();
                }
            }
        }
    }
}

#[tokio::test]
async fn slow_bodies_do_not_shed_token_requests() {
    let url = spawn_offline(
        Config {
            max_concurrent_requests: GATED_CAP,
            max_concurrent_per_identity: GATED_CAP,
            ..Config::default()
        },
        SERVICE_YAML,
    )
    .await;
    let addr = url.trim_start_matches("http://").to_owned();

    let mut senders = Vec::new();
    for _ in 0..SLOW_SENDERS {
        let stream = slow_sender(&addr).await;
        senders.push(tokio::spawn(dribble(stream)));
    }
    // Let every slow request reach the router.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "unknown"),
            ("code_verifier", "unknown"),
        ])
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("token response");
    assert_ne!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "slow bodies held the OAuth budget: {:?}",
        response.text().await
    );
    let mcp = client
        .post(format!("{url}/mcp"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .expect("mcp response");
    assert_eq!(mcp.status(), StatusCode::OK, "/mcp shares no OAuth budget");

    for sender in senders {
        let verdict = tokio::time::timeout(Duration::from_secs(15), sender)
            .await
            .expect("slow body answered within the deadline")
            .expect("sender task");
        assert!(
            verdict.starts_with("HTTP/1.1 408"),
            "an unfinished body is a request timeout, got: {verdict}"
        );
    }
}
