//! TCP and TLS delivery against in-process loopback receivers: RFC 5425
//! octet framing, reconnect after the receiver drops the connection, CA
//! pinning, and the CA file's boot-time errors.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::net::TcpListener;
use uuid::Uuid;

use super::{SyslogTls, SyslogTlsError, SyslogTransport};
use crate::audit::drain::DetachedTasks;
use crate::audit::stream::StreamSinks;
use crate::audit::{AuditRow, OutcomeCode};

const WAIT: Duration = Duration::from_secs(5);

fn row(request_id: &str) -> AuditRow {
    AuditRow {
        id: Uuid::new_v4(),
        request_id: request_id.into(),
        user_sub: "user-1".into(),
        user_email: "u@example.com".into(),
        groups: vec![],
        tool: "run_query".into(),
        server: Some("prod".into()),
        database: Some("app".into()),
        // A newline inside the row: newline framing would split it in two.
        sql: Some("SELECT 1\nFROM t".into()),
        reason: None,
        outcome: OutcomeCode::Abandoned,
        elapsed_ms: None,
        row_count: None,
        truncated: None,
        error_message: None,
        agent_client: None,
        ip: None,
        db_type: Some("postgres".into()),
        upstream_actor: None,
        upstream_run_id: None,
        rows_affected: None,
        sql_truncated: false,
    }
}

/// Read one RFC 5425 frame: `MSG-LEN SP MSG`.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> String {
    let mut len = Vec::new();
    reader.read_until(b' ', &mut len).await.expect("length");
    let len: usize = std::str::from_utf8(&len[..len.len() - 1])
        .expect("ascii length")
        .parse()
        .expect("numeric length");
    let mut message = vec![0; len];
    reader.read_exact(&mut message).await.expect("message");
    String::from_utf8(message).expect("utf-8 message")
}

#[tokio::test]
async fn tcp_sink_sends_octet_framed_rows_on_one_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let sinks = StreamSinks::syslog("127.0.0.1".into(), port, SyslogTransport::Tcp);
    let tasks = DetachedTasks::new();

    sinks.send(&row("req-tcp-1"), &tasks);
    let (socket, _) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut reader = BufReader::new(socket);
    let first = tokio::time::timeout(WAIT, read_frame(&mut reader))
        .await
        .unwrap();
    assert!(first.starts_with("<134>1 "), "{first}");
    assert!(first.contains("req-tcp-1"), "{first}");
    assert!(first.contains(r"SELECT 1\nFROM t"), "{first}");

    sinks.send(&row("req-tcp-2"), &tasks);
    let second = tokio::time::timeout(WAIT, read_frame(&mut reader))
        .await
        .unwrap();
    assert!(second.contains("req-tcp-2"), "same connection: {second}");
}

/// A receiver restart closes the stream; the sink reconnects instead of
/// writing into the dead connection forever.
#[tokio::test]
async fn tcp_sink_reconnects_after_the_receiver_drops_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let sinks = StreamSinks::syslog("127.0.0.1".into(), port, SyslogTransport::Tcp);
    let tasks = DetachedTasks::new();

    sinks.send(&row("req-before"), &tasks);
    let (socket, _) = listener.accept().await.unwrap();
    let mut reader = BufReader::new(socket);
    read_frame(&mut reader).await;
    drop(reader);

    // The first write after the close can still land in the kernel buffer,
    // so keep sending until a row reaches a fresh connection.
    let delivered = tokio::time::timeout(WAIT, async {
        let mut attempt = 0;
        loop {
            attempt += 1;
            sinks.send(&row(&format!("req-after-{attempt}")), &tasks);
            let accepted =
                tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            if let Ok(Ok((socket, _))) = accepted {
                return read_frame(&mut BufReader::new(socket)).await;
            }
        }
    })
    .await
    .expect("sink reconnected");
    assert!(delivered.contains("req-after-"), "{delivered}");
}

struct Pki {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ca_pem: String,
}

fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![san.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca)
        .unwrap();
    Pki {
        chain: vec![leaf.der().clone(), ca.der().clone()],
        key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        ca_pem: ca.pem(),
    }
}

/// TLS receiver on loopback presenting `server`'s chain; yields the first
/// frame of the first connection whose handshake completes.
async fn tls_receiver(server: Pki) -> (u16, tokio::task::JoinHandle<String>) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(server.chain, server.key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let frame = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(stream) = acceptor.accept(socket).await {
                return read_frame(&mut BufReader::new(stream)).await;
            }
        }
    });
    (port, frame)
}

fn ca_file(pem: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(pem.as_bytes()).unwrap();
    file
}

#[tokio::test]
async fn tls_sink_delivers_to_a_receiver_signed_by_the_pinned_ca() {
    let server = pki("localhost");
    let ca = ca_file(&server.ca_pem);
    let (port, frame) = tls_receiver(server).await;
    let tls = SyslogTls::from_ca_file(ca.path()).expect("CA loads");

    StreamSinks::syslog("localhost".into(), port, SyslogTransport::Tls(tls))
        .send(&row("req-tls"), &DetachedTasks::new());

    let frame = tokio::time::timeout(WAIT, frame).await.unwrap().unwrap();
    assert!(frame.contains("req-tls"), "{frame}");
}

/// A receiver whose certificate chains to another CA gets no row.
#[tokio::test]
async fn tls_sink_refuses_a_receiver_outside_the_pinned_ca() {
    let (port, frame) = tls_receiver(pki("localhost")).await;
    let other_ca = ca_file(&pki("localhost").ca_pem);
    let tls = SyslogTls::from_ca_file(other_ca.path()).unwrap();
    let tasks = DetachedTasks::new();

    StreamSinks::syslog("localhost".into(), port, SyslogTransport::Tls(tls))
        .send(&row("req-untrusted"), &tasks);

    tasks.drain(WAIT).await.expect("delivery attempt finishes");
    assert!(!frame.is_finished(), "no handshake may complete");
    frame.abort();
}

#[test]
fn ca_file_errors_are_typed() {
    let missing = SyslogTls::from_ca_file(std::path::Path::new("/nonexistent/ca.pem"));
    assert!(matches!(missing, Err(SyslogTlsError::Read { .. })));

    let empty = ca_file("not a certificate\n");
    let no_cert = SyslogTls::from_ca_file(empty.path());
    assert!(matches!(no_cert, Err(SyslogTlsError::NoCertificate { .. })));
}
