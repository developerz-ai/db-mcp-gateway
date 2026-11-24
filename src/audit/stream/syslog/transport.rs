//! One open connection to a syslog receiver, per transport: UDP datagrams,
//! or an RFC 5425 octet-framed byte stream over TCP or TLS.

use std::net::SocketAddr;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;

use super::format::octet_frame;
use super::tls::SyslogTls;

/// Hard ceiling on any single delivery step (DNS resolution, bind, connect,
/// TLS handshake, write), so a wedged resolver or black-holed receiver sheds
/// a row instead of holding the connection forever.
const STEP_TIMEOUT: Duration = Duration::from_secs(5);

/// How a syslog sink reaches its receiver.
#[derive(Debug, Clone)]
pub enum SyslogTransport {
    /// RFC 5426: one datagram per row. Silent loss on a down receiver.
    Udp,
    /// RFC 6587 octet counting over plain TCP: a refused or reset connection
    /// is seen and counted as a drop.
    Tcp,
    /// RFC 5425: TCP wrapped in TLS, receiver verified against [`SyslogTls`].
    Tls(SyslogTls),
}

impl SyslogTransport {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls(_) => "tls",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum DeliveryError {
    #[error("DNS resolution failed")]
    Resolve(#[source] std::io::Error),
    #[error("host resolved to no addresses")]
    NoAddress,
    #[error("local UDP bind failed")]
    Bind(#[source] std::io::Error),
    #[error("TCP connect failed")]
    Connect(#[source] std::io::Error),
    #[error("host is not a valid TLS server name")]
    ServerName,
    #[error("TLS handshake failed")]
    Handshake(#[source] std::io::Error),
    #[error("send failed")]
    Send(#[source] std::io::Error),
    #[error("{0} timed out")]
    TimedOut(&'static str),
    #[error("too many rows in flight to this receiver")]
    Busy,
}

#[derive(Debug)]
pub(super) enum Connection {
    Udp { socket: UdpSocket, addr: SocketAddr },
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Connection {
    pub(super) async fn open(
        host: &str,
        port: u16,
        transport: &SyslogTransport,
    ) -> Result<Self, DeliveryError> {
        let addrs = resolve(host, port).await?;
        match transport {
            SyslogTransport::Udp => {
                // A datagram cannot tell a dead receiver from a live one, so
                // there is nothing to fall back on: the first address it is.
                let addr = *addrs.first().ok_or(DeliveryError::NoAddress)?;
                // Unspecified local port on the matching family; `send_to`
                // names the receiver, so no `connect()`.
                let bind_addr = if addr.is_ipv6() {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                let socket = step("local UDP bind", UdpSocket::bind(bind_addr))
                    .await?
                    .map_err(DeliveryError::Bind)?;
                Ok(Self::Udp { socket, addr })
            }
            SyslogTransport::Tcp => Ok(Self::Tcp(connect(&addrs).await?)),
            SyslogTransport::Tls(tls) => {
                let name =
                    ServerName::try_from(host.to_owned()).map_err(|_| DeliveryError::ServerName)?;
                let tcp = connect(&addrs).await?;
                let stream = step("TLS handshake", tls.connector().connect(name, tcp))
                    .await?
                    .map_err(DeliveryError::Handshake)?;
                Ok(Self::Tls(Box::new(stream)))
            }
        }
    }

    /// Send one message: as-is in a datagram, octet-framed on a stream.
    pub(super) async fn send(&mut self, message: &str) -> Result<(), DeliveryError> {
        let sent = match self {
            Self::Udp { socket, addr } => step("send", socket.send_to(message.as_bytes(), *addr))
                .await?
                .map(drop),
            Self::Tcp(stream) => step("send", write_frame(stream, message)).await?,
            Self::Tls(stream) => step("send", write_frame(stream.as_mut(), message)).await?,
        };
        sent.map_err(DeliveryError::Send)
    }
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, DeliveryError> {
    let addrs: Vec<_> = step("DNS resolution", tokio::net::lookup_host((host, port)))
        .await?
        .map_err(DeliveryError::Resolve)?
        .collect();
    if addrs.is_empty() {
        return Err(DeliveryError::NoAddress);
    }
    Ok(addrs)
}

/// The first of `addrs` that accepts, in resolver order, all within one
/// [`STEP_TIMEOUT`]. Each address gets an even share of the time left, so a
/// black-holed first address cannot starve a healthy second one.
async fn connect(addrs: &[SocketAddr]) -> Result<TcpStream, DeliveryError> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    let mut last = DeliveryError::NoAddress;
    for (tried, addr) in addrs.iter().enumerate() {
        let untried = u32::try_from(addrs.len() - tried).unwrap_or(u32::MAX);
        let share = deadline.saturating_duration_since(Instant::now()) / untried;
        last = match tokio::time::timeout(share, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => DeliveryError::Connect(err),
            Err(_) => DeliveryError::TimedOut("TCP connect"),
        };
    }
    Err(last)
}

/// `flush` matters for TLS: the record is only on the wire once flushed.
async fn write_frame<W>(stream: &mut W, message: &str) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(octet_frame(message).as_bytes()).await?;
    stream.flush().await
}

async fn step<T>(what: &'static str, future: impl Future<Output = T>) -> Result<T, DeliveryError> {
    tokio::time::timeout(STEP_TIMEOUT, future)
        .await
        .map_err(|_| DeliveryError::TimedOut(what))
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    /// A host whose first address refuses still reaches the second.
    #[tokio::test]
    async fn connect_tries_each_resolved_address() {
        let refusing = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let refused = refusing.local_addr().expect("addr");
        drop(refusing);
        let healthy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let reachable = healthy.local_addr().expect("addr");

        let stream = connect(&[refused, reachable])
            .await
            .expect("second address");
        assert_eq!(stream.peer_addr().expect("peer"), reachable);
        assert!(matches!(
            connect(&[refused]).await,
            Err(DeliveryError::Connect(_))
        ));
    }
}
