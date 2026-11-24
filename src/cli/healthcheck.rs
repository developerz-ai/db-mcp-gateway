//! `--healthcheck`: GET this host's own `/healthz` and exit 0 on a 200. The
//! runtime image is distroless (no shell, curl or wget), so a container
//! `HEALTHCHECK` runs the gateway binary itself.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use db_mcp_gateway::config::Config;
use reqwest::StatusCode;

use super::{CliError, EXIT_FAILED, EXIT_OK};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run() -> Result<u8, CliError> {
    // The probe runs with the gateway's own environment, so it reads the
    // listener exactly as boot does.
    let config = Config::from_env().map_err(|err| CliError::Invalid(err.to_string()))?;
    let url = probe_url(config.bind, config.tls.is_enabled());
    match probe(&url).await {
        Ok(status) if status == StatusCode::OK => {
            println!("healthy: {url} answered {status}");
            Ok(EXIT_OK)
        }
        Ok(status) => {
            println!("unhealthy: {url} answered {status}");
            Ok(EXIT_FAILED)
        }
        Err(err) => {
            println!("unhealthy: {err}");
            Ok(EXIT_FAILED)
        }
    }
}

/// The status `/healthz` itself answered: no proxy from the environment and
/// no redirect may substitute another endpoint's answer.
async fn probe(url: &str) -> Result<StatusCode, CliError> {
    // Loopback, status code only, no credential sent: the certificate names
    // the public host, not 127.0.0.1, so it is not verified here.
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| CliError::unreachable(url, &err))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| CliError::unreachable(url, &err))?;
    Ok(response.status())
}

/// A wildcard bind is probed on the loopback address of its family.
fn probe_url(bind: SocketAddr, tls: bool) -> String {
    let ip = match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    let scheme = if tls { "https" } else { "http" };
    format!("{scheme}://{}/healthz", SocketAddr::new(ip, bind.port()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// One connection, answered with `head` whatever was asked.
    async fn answer_once(head: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/healthz", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(head.as_bytes()).await;
        });
        url
    }

    #[tokio::test]
    async fn only_a_direct_200_is_reported() {
        let redirect = answer_once(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/ok\r\ncontent-length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(probe(&redirect).await.unwrap(), StatusCode::FOUND);
        let no_content = answer_once("HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await;
        assert_eq!(probe(&no_content).await.unwrap(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn wildcard_binds_probe_loopback() {
        assert_eq!(
            probe_url("0.0.0.0:8443".parse().unwrap(), true),
            "https://127.0.0.1:8443/healthz"
        );
        assert_eq!(
            probe_url("[::]:8080".parse().unwrap(), false),
            "http://[::1]:8080/healthz"
        );
        assert_eq!(
            probe_url("10.0.0.5:9000".parse().unwrap(), false),
            "http://10.0.0.5:9000/healthz"
        );
    }
}
