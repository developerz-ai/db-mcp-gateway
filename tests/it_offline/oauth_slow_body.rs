//! Senders that dribble their request body must not pin the unauthenticated
//! OAuth budget: bodies are read before a concurrency permit is taken, so a
//! token request still gets through while slow bodies are in flight, and a
//! body that never completes is answered `408` without ever holding a permit.
//! `/mcp` keeps its own budget throughout.
//!
//! The budget itself is pinned too: a fully-received request that holds the
//! one permit (its handler waits on an IdP that never answers) sheds the
//! next OAuth request until it finishes.

use std::sync::Arc;
use std::time::Duration;

use crate::common::gateway::{
    SERVICE_TOKEN, SERVICE_YAML, bind, offline_state, serve, spawn_offline,
};
use db_mcp_gateway::auth::{AuthConfig, OidcClient};
use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport;
use reqwest::StatusCode;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};

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
    let response = token_request(&client, &url).await;
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

/// An IdP that accepts connections and answers nothing until `release`
/// fires, then hangs up. Each accepted connection is reported on the
/// returned channel.
async fn spawn_silent_idp(release: Arc<Notify>) -> (String, mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind IdP");
    let issuer = format!("http://{}", listener.local_addr().expect("IdP address"));
    let (accepted, accepts) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            tokio::select! {
                Ok((stream, _)) = listener.accept() => {
                    held.push(stream);
                    let _ = accepted.send(());
                }
                () = release.notified() => return,
            }
        }
    });
    (issuer, accepts)
}

async fn token_request(client: &reqwest::Client, url: &str) -> reqwest::Response {
    client
        .post(format!("{url}/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", "unknown"),
            ("code_verifier", "unknown"),
        ])
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("token response")
}

#[tokio::test]
async fn a_held_oauth_permit_sheds_the_next_oauth_request() {
    let release = Arc::new(Notify::new());
    let (issuer, mut idp_accepts) = spawn_silent_idp(release.clone()).await;
    let (listener, addr) = bind().await;
    let url = format!("http://{addr}");
    let mut state = offline_state(&url, SERVICE_YAML);
    state.oauth.auth.oidc = OidcClient::new(AuthConfig {
        issuer,
        ..AuthConfig::default()
    })
    .expect("oidc client");
    let config = Config {
        bind: addr,
        max_concurrent_requests: GATED_CAP,
        max_concurrent_per_identity: GATED_CAP,
        ..Config::default()
    };
    serve(
        listener,
        transport::router(&config, state).expect("router builds"),
    );
    let client = reqwest::Client::new();

    // `/auth/login` has no body to wait for: it takes the one permit and
    // holds it while its discovery request to the IdP goes unanswered.
    let held = tokio::spawn(client.post(format!("{url}/auth/login")).send());
    tokio::time::timeout(Duration::from_secs(5), idp_accepts.recv())
        .await
        .expect("the login reached the IdP")
        .expect("IdP task alive");

    let shed = token_request(&client, &url).await;
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(shed.headers()["retry-after"], "1");
    let body: serde_json::Value = shed.json().await.expect("shed body");
    assert_eq!(body["error"]["code"], "service_overloaded");

    let mcp = client
        .post(format!("{url}/mcp"))
        .bearer_auth(SERVICE_TOKEN)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .send()
        .await
        .expect("mcp response");
    assert_eq!(mcp.status(), StatusCode::OK, "/mcp shares no OAuth budget");

    // The IdP hangs up, the login fails, and its permit comes back.
    release.notify_one();
    let login = held.await.expect("join").expect("login response");
    assert!(login.status().is_server_error(), "got {}", login.status());
    let admitted = token_request(&client, &url).await;
    assert_eq!(
        admitted.status(),
        StatusCode::BAD_REQUEST,
        "the released permit admits the next request"
    );
}
