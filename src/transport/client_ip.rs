//! The client IP the audit row records. Behind a reverse proxy the TCP peer is
//! the proxy, so with `TRUSTED_PROXIES` set the client is read from
//! `X-Forwarded-For` — but only from hops a trusted proxy appended: the walk
//! starts at the peer and moves left while the hop is trusted, so an entry the
//! client wrote itself is never believed.

use std::net::{IpAddr, SocketAddr};

use std::convert::Infallible;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::header::HeaderName;
use axum::http::request::Parts;

const TRUSTED_PROXIES_VAR: &str = "TRUSTED_PROXIES";
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// A `TRUSTED_PROXIES` entry that is not an IP or `ip/prefix` CIDR.
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid {TRUSTED_PROXIES_VAR} entry `{0}`: expected a comma-separated list of \
     IPs or CIDRs (e.g. `10.0.0.0/8,fd00::/8`)"
)]
pub struct TrustedProxiesError(String);

/// Proxies whose `X-Forwarded-For` hop is believed. `Default` trusts none,
/// which is also what a router built without this extension does.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Cidr>);

#[derive(Debug, Clone, Copy)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl TrustedProxies {
    /// Read `TRUSTED_PROXIES` (unset or blank → none trusted).
    pub fn from_env() -> Result<Self, TrustedProxiesError> {
        Self::parse(&std::env::var(TRUSTED_PROXIES_VAR).unwrap_or_default())
    }

    pub fn parse(raw: &str) -> Result<Self, TrustedProxiesError> {
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        raw.split(',')
            .map(|entry| Cidr::parse(entry.trim()).ok_or_else(|| TrustedProxiesError(entry.into())))
            .collect::<Result<_, _>>()
            .map(Self)
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|cidr| cidr.contains(ip))
    }

    /// The client address for a request from `peer`: the right-most
    /// `X-Forwarded-For` hop not added by a trusted proxy. An unparsable hop
    /// ends the walk at the last trusted one rather than guessing past it.
    pub fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let mut client = peer.ip().to_canonical();
        let mut hops = forwarded_hops(headers).into_iter().rev();
        while self.trusts(client) {
            match hops.next().map(parse_hop) {
                Some(Some(hop)) => client = hop,
                Some(None) | None => break,
            }
        }
        client
    }
}

/// Extractor: the audited client IP of this request — `None` only when the
/// server was started without connect info (in-process test routers).
#[derive(Debug, Clone, Copy)]
pub(super) struct ClientIp(pub(super) Option<IpAddr>);

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Infallible> {
        let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
            return Ok(Self(None));
        };
        let proxies = parts.extensions.get::<TrustedProxies>();
        let ip = proxies.map_or(peer.ip().to_canonical(), |proxies| {
            proxies.client_ip(*peer, &parts.headers)
        });
        Ok(Self(Some(ip)))
    }
}

impl Cidr {
    fn parse(entry: &str) -> Option<Self> {
        let (addr, prefix) = match entry.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix.parse::<u8>().ok()?)),
            None => (entry, None),
        };
        let network = addr.parse::<IpAddr>().ok()?.to_canonical();
        let max = max_prefix(network);
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Self { network, prefix })
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => same_prefix(
                u128::from(net.to_bits()),
                u128::from(ip.to_bits()),
                32,
                self.prefix,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                same_prefix(net.to_bits(), ip.to_bits(), 128, self.prefix)
            }
            _ => false,
        }
    }
}

fn max_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

/// Do the top `prefix` of `width` bits of `a` and `b` agree?
fn same_prefix(a: u128, b: u128, width: u32, prefix: u8) -> bool {
    let shift = width - u32::from(prefix);
    a.checked_shr(shift).unwrap_or(0) == b.checked_shr(shift).unwrap_or(0)
}

/// Every `X-Forwarded-For` hop, left to right across repeated headers. A
/// non-UTF-8 header contributes one hop that will not parse.
fn forwarded_hops(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .flat_map(|value| value.to_str().unwrap_or("?").split(','))
        .map(str::trim)
        .collect()
}

/// A hop is a bare IP, or an `ip:port` / `[v6]:port` some proxies write.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    hop.parse::<IpAddr>()
        .or_else(|_| hop.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 40000)
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(X_FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn ip(raw: &str) -> IpAddr {
        raw.parse().unwrap()
    }

    #[test]
    fn untrusted_peer_is_the_client_whatever_it_forwards() {
        let none = TrustedProxies::default();
        let headers = xff(&["203.0.113.7"]);
        assert_eq!(none.client_ip(peer("10.0.0.5"), &headers), ip("10.0.0.5"));
        let lb = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            lb.client_ip(peer("198.51.100.1"), &headers),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn trusted_peer_yields_the_rightmost_untrusted_hop() {
        let proxies = TrustedProxies::parse("10.0.0.0/8, 192.168.1.5").unwrap();
        // The client forged `1.1.1.1`; the edge proxy appended the real peer.
        let headers = xff(&["1.1.1.1, 203.0.113.7", "192.168.1.5"]);
        assert_eq!(
            proxies.client_ip(peer("10.0.0.5"), &headers),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn trusted_peer_without_a_usable_hop_stays_the_peer() {
        let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            proxies.client_ip(peer("10.0.0.5"), &HeaderMap::new()),
            ip("10.0.0.5")
        );
        let garbage = xff(&["203.0.113.7, not-an-ip"]);
        assert_eq!(
            proxies.client_ip(peer("10.0.0.5"), &garbage),
            ip("10.0.0.5")
        );
        let all_trusted = xff(&["10.1.1.1, 10.2.2.2"]);
        assert_eq!(
            proxies.client_ip(peer("10.0.0.5"), &all_trusted),
            ip("10.1.1.1")
        );
    }

    #[test]
    fn hops_with_ports_and_mapped_v6_peers_resolve() {
        let proxies = TrustedProxies::parse("10.0.0.0/8,fd00::/8").unwrap();
        let headers = xff(&["[2001:db8::1]:443"]);
        assert_eq!(
            proxies.client_ip(peer("::ffff:10.0.0.5"), &headers),
            ip("2001:db8::1")
        );
        let headers = xff(&["203.0.113.7:5000"]);
        assert_eq!(
            proxies.client_ip(peer("fd00::1"), &headers),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn prefix_zero_and_full_width_are_honoured() {
        let all = TrustedProxies::parse("0.0.0.0/0").unwrap();
        assert!(all.trusts(ip("203.0.113.7")));
        assert!(!all.trusts(ip("::1")), "a v4 range never matches v6");
        let one = TrustedProxies::parse("::1/128").unwrap();
        assert!(one.trusts(ip("::1")));
        assert!(!one.trusts(ip("::2")));
    }

    #[test]
    fn malformed_entries_fail_boot() {
        for bad in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0",
            "proxy.internal",
            "10.0.0.0/8,",
            "*",
        ] {
            assert!(TrustedProxies::parse(bad).is_err(), "{bad:?} accepted");
        }
    }
}
