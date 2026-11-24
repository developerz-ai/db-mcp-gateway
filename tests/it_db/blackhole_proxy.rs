//! Test support for `permissions_listener_liveness_real_db`: a TCP proxy that
//! reproduces a *silent* connection drop against the real state DB.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// TCP forwarder in front of the state DB that can blackhole the connection
/// carrying `LISTEN`: bytes stop both ways, the sockets stay open.
pub struct Proxy {
    pub addr: SocketAddr,
    conns: Arc<Mutex<Vec<Arc<Conn>>>>,
}

#[derive(Default)]
struct Conn {
    is_listener: AtomicBool,
    frozen: CancellationToken,
}

impl Proxy {
    pub async fn start(upstream: (String, u16)) -> Self {
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let conns: Arc<Mutex<Vec<Arc<Conn>>>> = Arc::default();
        let registry = conns.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = socket.accept().await {
                let conn = Arc::new(Conn::default());
                registry.lock().unwrap().push(conn.clone());
                tokio::spawn(forward(client, upstream.clone(), conn));
            }
        });
        Self { addr, conns }
    }

    /// Blackhole every connection that has sent `LISTEN`; returns how many.
    pub fn freeze_listeners(&self) -> usize {
        let conns = self.conns.lock().unwrap();
        let listeners = conns
            .iter()
            .filter(|c| c.is_listener.load(Ordering::SeqCst));
        listeners.map(|c| c.frozen.cancel()).count()
    }
}

async fn forward(mut client: TcpStream, upstream: (String, u16), conn: Arc<Conn>) {
    let Ok(mut server) = TcpStream::connect(upstream).await else {
        return;
    };
    let (mut from_client, mut from_server) = ([0u8; 8192], [0u8; 8192]);
    loop {
        tokio::select! {
            // Holds both sockets open and silent until the test ends.
            () = conn.frozen.cancelled() => std::future::pending::<()>().await,
            read = client.read(&mut from_client) => {
                let Ok(n @ 1..) = read else { return };
                if from_client[..n].windows(6).any(|w| w == b"LISTEN") {
                    conn.is_listener.store(true, Ordering::SeqCst);
                }
                if server.write_all(&from_client[..n]).await.is_err() {
                    return;
                }
            }
            read = server.read(&mut from_server) => {
                let Ok(n @ 1..) = read else { return };
                if client.write_all(&from_server[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}
