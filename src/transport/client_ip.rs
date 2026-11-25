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
/// Prefix length of `::ffff:0:0/96`, the IPv4-mapped block.
const MAPPED_PREFIX: u8 = 96;

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
        // Kept in its written family: a mapped entry's prefix counts v6 bits.
        let network = addr.parse::<IpAddr>().ok()?;
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
            // Only an entry inside `::ffff:0:0/96` names v4 addresses: a
            // plain v6 range such as `::/0` would otherwise trust every v4
            // peer through its mapped form.
            (IpAddr::V6(net), IpAddr::V4(ip)) => {
                net.to_ipv4_mapped().is_some()
                    && self.prefix >= MAPPED_PREFIX
                    && same_prefix(
                        net.to_bits(),
                        ip.to_ipv6_mapped().to_bits(),
                        128,
                        self.prefix,
                    )
            }
            (IpAddr::V4(_), IpAddr::V6(_)) => false,
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

/// Every `X-Forwarded-For` hop, left to right across repeated headers. Split
/// as bytes, so a non-ASCII entry a client forged costs only its own hop, not
/// the hops trusted proxies appended after it.
fn forwarded_hops(headers: &HeaderMap) -> Vec<&[u8]> {
    headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .flat_map(|value| value.as_bytes().split(|&byte| byte == b','))
        .map(<[u8]>::trim_ascii)
        .collect()
}

/// A hop is a bare IP, or an `ip:port` / `[v6]:port` some proxies write.
/// Non-UTF-8 is no IP: the walk stops at the trusted hop before it.
fn parse_hop(hop: &[u8]) -> Option<IpAddr> {
    let hop = std::str::from_utf8(hop).ok()?;
    hop.parse::<IpAddr>()
        .or_else(|_| hop.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
#[path = "client_ip_tests.rs"]
mod tests;
