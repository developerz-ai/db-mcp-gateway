//! A loopback `http://` gateway is reached directly: an `HTTP_PROXY` in the
//! environment must never receive the admin bearer in plaintext.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::cli_check::gateway;

/// Accept one connection on `listener` (if any arrives within the wait),
/// answer it with an empty JSON list, and report whether it came.
fn answer_once(listener: TcpListener) -> mpsc::Receiver<bool> {
    let (tx, rx) = mpsc::channel();
    listener.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || {
        for _ in 0..100 {
            if let Ok((mut stream, _)) = listener.accept() {
                stream.set_nonblocking(false).expect("blocking");
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n[]",
                );
                let _ = tx.send(true);
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = tx.send(false);
    });
    rx
}

#[test]
fn a_loopback_http_gateway_bypasses_the_environment_proxy() {
    let gw = TcpListener::bind("127.0.0.1:0").expect("gateway listener");
    let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy listener");
    let gw_url = format!("http://127.0.0.1:{}", gw.local_addr().unwrap().port());
    let proxy_url = format!("http://127.0.0.1:{}", proxy.local_addr().unwrap().port());

    let dir = tempfile::tempdir().expect("tempdir");
    let session = dir.path().join("session.json");
    fs::write(
        &session,
        format!(r#"{{"url":"{gw_url}","access_token":"not-a-real-bearer"}}"#),
    )
    .expect("session file");
    fs::set_permissions(&session, fs::Permissions::from_mode(0o600)).expect("0600");

    let gw_hit = answer_once(gw);
    let proxy_hit = answer_once(proxy);
    let session = session.to_str().expect("utf-8 path");
    let _ = gateway(
        &["grants", "list", "--token-file", session],
        &[
            ("HTTP_PROXY", &proxy_url),
            ("http_proxy", &proxy_url),
            ("ALL_PROXY", &proxy_url),
            ("NO_PROXY", ""),
        ],
    );

    assert!(
        gw_hit.recv().expect("gateway result"),
        "the CLI never reached the loopback gateway"
    );
    assert!(
        !proxy_hit.recv().expect("proxy result"),
        "the admin request went through the environment proxy"
    );
}
