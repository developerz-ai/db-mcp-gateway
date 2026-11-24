//! `--healthcheck`: GET this host's own `/healthz` and exit 0 on a 200. The
//! runtime image is distroless (no shell, curl or wget), so a container
//! `HEALTHCHECK` runs the gateway binary itself.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use db_mcp_gateway::config::Config;

use super::{CliError, EXIT_FAILED, EXIT_OK};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run() -> Result<u8, CliError> {
    // The probe runs with the gateway's own environment, so it reads the
    // listener exactly as boot does.
    let config = Config::from_env().map_err(|err| CliError::Invalid(err.to_string()))?;
    let url = probe_url(config.bind, config.tls.is_enabled());
    // Loopback, status code only, no credential sent: the certificate names
    // the public host, not 127.0.0.1, so it is not verified here.
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .tls_danger_accept_invalid_certs(true)
        .build()
        .map_err(|err| CliError::unreachable(&url, &err))?;
    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            println!("healthy: {url} answered {}", response.status());
            Ok(EXIT_OK)
        }
        Ok(response) => {
            println!("unhealthy: {url} answered {}", response.status());
            Ok(EXIT_FAILED)
        }
        Err(err) => {
            println!("unhealthy: {}", CliError::unreachable(&url, &err));
            Ok(EXIT_FAILED)
        }
    }
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
    use super::probe_url;

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
