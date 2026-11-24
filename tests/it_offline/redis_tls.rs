//! `kind: redis` TLS verification against an in-process TLS server whose
//! certificates are minted per test (rcgen). The server speaks just enough
//! RESP to answer `AUTH`/`SELECT` (`+OK`) and every other command (`:7`), and
//! counts the commands it received — so a refused handshake is proven to
//! have sent nothing, credentials included.
//!
//! `tls: required` and `verify_full` must verify the chain and the hostname;
//! `tls_ca_file` replaces the system roots. An accept-any verifier would pass
//! the wrong-CA and hostname-mismatch cases and fail this file.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use db_mcp_gateway::config::{Database, Password, Server, ServerKind, Tls};
use db_mcp_gateway::exec::{Access, DbAdapter, ExecError, ExecQuery, PoolSizing, RedisAdapter};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tempfile::TempDir;

const HOST: &str = "127.0.0.1";

/// A CA and a leaf it signed for `san`, as the server's chain + key and the
/// CA's PEM for the client.
struct Pki {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    ca_pem: String,
}

fn pki(san: &str) -> Pki {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("CA cert");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = CertificateParams::new(vec![san.to_string()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca)
        .expect("leaf cert");
    Pki {
        chain: vec![leaf.der().clone(), ca.der().clone()],
        key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        ca_pem: ca.pem(),
    }
}

/// Serve TLS + minimal RESP on a free port; returns the port and the count
/// of commands received after a completed handshake.
fn serve(pki: Pki) -> (u16, Arc<AtomicUsize>) {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(pki.chain, pki.key)
        .expect("server config");
    let config = Arc::new(config);
    let listener = TcpListener::bind((HOST, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let commands = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&commands);
    std::thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            let counter = Arc::clone(&counter);
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let stream = rustls::StreamOwned::new(conn, socket);
                let _ = answer_resp(BufReader::new(stream), &counter);
            });
        }
    });
    (port, commands)
}

fn answer_resp<S: Read + Write>(
    mut reader: BufReader<S>,
    counter: &AtomicUsize,
) -> std::io::Result<()> {
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let argc: usize = line.trim_start_matches('*').trim().parse().unwrap_or(0);
        let mut name = String::new();
        for i in 0..argc {
            let mut header = String::new();
            reader.read_line(&mut header)?;
            let len: usize = header.trim_start_matches('$').trim().parse().unwrap_or(0);
            let mut arg = vec![0; len + 2];
            reader.read_exact(&mut arg)?;
            if i == 0 {
                name = String::from_utf8_lossy(&arg[..len]).to_ascii_uppercase();
            }
        }
        counter.fetch_add(1, Ordering::SeqCst);
        let reply: &[u8] = if matches!(name.as_str(), "AUTH" | "SELECT") {
            b"+OK\r\n"
        } else {
            b":7\r\n"
        };
        reader.get_mut().write_all(reply)?;
        reader.get_mut().flush()?;
    }
}

fn target(port: u16, tls: Tls, tls_ca_file: Option<PathBuf>) -> (Server, Database) {
    let database = Database {
        name: "0".into(),
        role: "gateway_ro".into(),
        password: Password::Literal("pw".into()),
        description: String::new(),
        auth_database: None,
        connect_name: None,
        pool: None,
        write_role: None,
        write_password: None,
    };
    let server = Server {
        name: "tls".into(),
        kind: ServerKind::Redis,
        description: String::new(),
        host: HOST.into(),
        port,
        tls,
        tls_ca_file,
        pool: None,
        databases: vec![database.clone()],
    };
    (server, database)
}

/// The handshake failure arrives as an I/O error (`Unavailable`); both it
/// and `Connection` are the client's `unavailable`. The zero command count
/// each caller also asserts is the real proof.
fn assert_refused(err: &ExecError) {
    assert!(
        matches!(err, ExecError::Unavailable | ExecError::Connection),
        "{err:?}"
    );
}

async fn dbsize(server: &Server, database: &Database) -> Result<serde_json::Value, ExecError> {
    let adapter = RedisAdapter::open(server, database, PoolSizing::default()).await?;
    let result = adapter
        .execute(ExecQuery {
            sql: r#"["DBSIZE"]"#,
            binds: &[],
            statement_timeout_ms: Some(5_000),
            row_limit: 10,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::new_v4(),
        })
        .await?;
    Ok(json!(result.rows))
}

fn ca_file(dir: &TempDir, pem: &str) -> PathBuf {
    let path = dir.path().join("ca.pem");
    std::fs::write(&path, pem).expect("write CA");
    path
}

#[tokio::test]
async fn verify_full_with_the_right_ca_and_hostname_connects() {
    db_mcp_gateway::transport::tls::install_crypto_provider();
    let pki = pki(HOST);
    let dir = TempDir::new().expect("tempdir");
    let ca = ca_file(&dir, &pki.ca_pem);
    let (port, commands) = serve(pki);
    let (server, database) = target(port, Tls::VerifyFull, Some(ca));
    assert_eq!(
        dbsize(&server, &database).await.expect("TLS read"),
        json!([[7]])
    );
    assert!(
        commands.load(Ordering::SeqCst) >= 2,
        "AUTH + DBSIZE reached the server"
    );
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused_before_auth() {
    db_mcp_gateway::transport::tls::install_crypto_provider();
    let served = pki(HOST);
    let other = pki(HOST);
    let dir = TempDir::new().expect("tempdir");
    let ca = ca_file(&dir, &other.ca_pem);
    let (port, commands) = serve(served);
    let (server, database) = target(port, Tls::VerifyFull, Some(ca));
    let err = dbsize(&server, &database).await.expect_err("untrusted CA");
    assert_refused(&err);
    assert_eq!(commands.load(Ordering::SeqCst), 0, "no command, no AUTH");
}

#[tokio::test]
async fn a_hostname_mismatch_is_refused_before_auth() {
    db_mcp_gateway::transport::tls::install_crypto_provider();
    let pki = pki("other.example");
    let dir = TempDir::new().expect("tempdir");
    let ca = ca_file(&dir, &pki.ca_pem);
    let (port, commands) = serve(pki);
    let (server, database) = target(port, Tls::VerifyFull, Some(ca));
    let err = dbsize(&server, &database)
        .await
        .expect_err("wrong hostname");
    assert_refused(&err);
    assert_eq!(commands.load(Ordering::SeqCst), 0);
}

/// `tls: required` verifies against the system roots, which do not hold a
/// test CA: an unverified `required` (Postgres' `sslmode=require`) would
/// connect here.
#[tokio::test]
async fn required_verifies_against_the_system_roots() {
    db_mcp_gateway::transport::tls::install_crypto_provider();
    let (port, commands) = serve(pki(HOST));
    let (server, database) = target(port, Tls::Required, None);
    let err = dbsize(&server, &database)
        .await
        .expect_err("self-signed CA");
    assert_refused(&err);
    assert_eq!(commands.load(Ordering::SeqCst), 0);
}
