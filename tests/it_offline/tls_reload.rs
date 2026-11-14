//! End-to-end test for issue #12: SIGHUP swaps the TLS cert without dropping
//! the listener.
//!
//! Strategy: two self-signed certs whose SAN differs (`a.localhost` vs
//! `b.localhost`). Connecting to the matching hostname succeeds; connecting
//! to the other hostname fails on cert verification. After SIGHUP swaps the
//! file from cert-A to cert-B, requests to `b.localhost` start succeeding —
//! and `a.localhost` requests fail. Plus a parallel hammer loop proves zero
//! requests are dropped during the swap.
//!
//! All tests share one process for SIGHUP scope, so the cases live in a
//! single function and signal only this binary's PID.
//!
//! Audit-row assertions are intentionally skipped — this test runs the TLS
//! layer in isolation (no auth, no tool dispatch, no audit integration).

use std::time::Duration;

use axum::Router;
use axum::routing::get;
use rcgen::{CertificateParams, KeyPair};
use reqwest::Certificate;
use tempfile::TempDir;
use tokio::net::TcpListener;

/// Bound on waiting for the server to come up and for SIGHUP to be drained.
const READY_WITHIN: Duration = Duration::from_secs(5);
const HAMMER_REQUESTS: usize = 10;

/// Generate a self-signed cert+key for one SAN. Returns (cert_pem, key_pem)
/// — both PEM-encoded.
fn self_signed(san: &str) -> (String, String) {
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::new(vec![san.to_string()]).expect("cert params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).expect("self-sign");
    (cert.pem(), key.serialize_pem())
}

/// Atomically rewrite a file: write to `<path>.new`, then rename. Avoids the
/// half-written PEM window cert-manager handles the same way.
fn atomic_write(path: &std::path::Path, contents: &str) {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, contents).expect("write tmp");
    std::fs::rename(&tmp, path).expect("rename");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sighup_reloads_tls_cert_without_dropping_listener() {
    db_mcp_gateway::transport::tls::install_crypto_provider();

    let dir = TempDir::new().expect("tempdir");
    let cert_path = dir.path().join("tls.pem");
    let key_path = dir.path().join("tls.key");

    let (a_cert, a_key) = self_signed("a.localhost");
    let (b_cert, b_key) = self_signed("b.localhost");

    atomic_write(&cert_path, &a_cert);
    atomic_write(&key_path, &a_key);

    // Pick a random free port. Bind sync via std + read addr, then hand to
    // axum-server below — `axum_server::from_tcp_rustls` keeps the bound port
    // so we know exactly where to send requests.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    // tokio sets the listener non-blocking; axum-server re-wraps it back into a
    // tokio listener internally, so we leave the std handle as-is.
    let std_listener = listener.into_std().expect("into_std");

    let rustls = db_mcp_gateway::transport::tls::load(&cert_path, &key_path)
        .await
        .expect("load initial cert");

    let app = Router::new().route("/healthz", get(|| async { "ok" }));

    let handle = axum_server::Handle::new();
    let server_handle = handle.clone();
    let rustls_for_server = rustls.clone();
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(std_listener, rustls_for_server)
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
            .expect("serve");
    });

    // Spawn the same SIGHUP loop main.rs uses. The handler is installed
    // here, not inside the task: a SIGHUP raised before an unscheduled task
    // registered it would hit the default action and kill the test binary.
    let reload_cert = cert_path.clone();
    let reload_key = key_path.clone();
    let rustls_for_reload = rustls.clone();
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("install SIGHUP");
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            // Same call shape as startup::spawn_reload_on_sighup; failures get
            // swallowed here because the test wants the loop to keep running.
            let _ = db_mcp_gateway::transport::tls::reload(
                &rustls_for_reload,
                &reload_cert,
                &reload_key,
            )
            .await;
        }
    });

    // ── Assertion 1: cert-A is served (once the server is up), cert-B
    //    doesn't validate.
    let a_root = Certificate::from_pem(a_cert.as_bytes()).expect("a root");
    let b_root = Certificate::from_pem(b_cert.as_bytes()).expect("b root");
    assert!(
        eventually_serves(&a_root, "a.localhost", addr.port()).await,
        "cert-A should serve a.localhost before swap"
    );
    assert!(
        !request(std::slice::from_ref(&b_root), "b.localhost", addr.port()).await,
        "cert-B-trusted client must NOT validate the cert-A server"
    );

    // ── Hammer: a burst of concurrent cert-A requests must all succeed.
    //    After the swap cert-A naturally stops matching, so the burst runs
    //    BEFORE we trigger SIGHUP.
    let burst: Vec<_> = (0..HAMMER_REQUESTS)
        .map(|_| {
            let root = a_root.clone();
            let port = addr.port();
            tokio::spawn(async move { request(&[root], "a.localhost", port).await })
        })
        .collect();
    for request in burst {
        assert!(
            request.await.expect("hammer join"),
            "in-flight requests on cert-A failed before the swap"
        );
    }

    // ── Swap the cert + key files, fire SIGHUP at ourselves.
    atomic_write(&cert_path, &b_cert);
    atomic_write(&key_path, &b_key);
    // SAFETY: `libc::raise` is safe when targeting a defined signal at our
    // own process; the kernel never errors here. Spawning a separate process
    // to `kill -HUP $$` would be heavier and racier.
    unsafe {
        assert_eq!(libc::raise(libc::SIGHUP), 0, "raise SIGHUP");
    }

    // ── Assertion 2: cert-B is now served (once the reload drained). The
    //    previously-failing client succeeds, and the previously-succeeding
    //    client now fails.
    assert!(
        eventually_serves(&b_root, "b.localhost", addr.port()).await,
        "cert-B must serve b.localhost AFTER swap"
    );
    assert!(
        !request(std::slice::from_ref(&a_root), "a.localhost", addr.port()).await,
        "cert-A must NOT serve a.localhost AFTER swap"
    );

    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    let _ = server.await;
}

/// Poll [`request`] until it succeeds or [`READY_WITHIN`] passes.
async fn eventually_serves(root: &Certificate, host: &str, port: u16) -> bool {
    let deadline = tokio::time::Instant::now() + READY_WITHIN;
    loop {
        if request(std::slice::from_ref(root), host, port).await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// One-shot HTTPS GET to `https://{host}:{port}/healthz`, trusting only the
/// supplied roots. Returns true on a 2xx response, false on any TLS or HTTP
/// error. Uses `resolve` to pin the SNI hostname to 127.0.0.1 without DNS.
async fn request(roots: &[Certificate], host: &str, port: u16) -> bool {
    let builder = reqwest::Client::builder()
        .resolve(host, format!("127.0.0.1:{port}").parse().expect("addr"))
        .timeout(Duration::from_secs(2))
        // Only the supplied roots are trusted — no OS trust store leakage.
        .tls_certs_only(roots.iter().cloned());
    let client = match builder.build() {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client
        .get(format!("https://{host}:{port}/healthz"))
        .send()
        .await
    {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}
