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
fn mapped_v6_entries_keep_their_v6_prefix() {
    let mapped_net = TrustedProxies::parse("::ffff:10.0.0.0/104").unwrap();
    assert!(mapped_net.trusts(ip("10.1.2.3")));
    assert!(mapped_net.trusts(ip("::ffff:10.1.2.3")));
    assert!(!mapped_net.trusts(ip("11.0.0.1")));
    let mapped_host = TrustedProxies::parse("::ffff:10.0.0.5/128").unwrap();
    assert!(mapped_host.trusts(ip("10.0.0.5")));
    assert!(!mapped_host.trusts(ip("10.0.0.6")));
    let every_v4 = TrustedProxies::parse("::ffff:0:0/96").unwrap();
    assert!(every_v4.trusts(ip("203.0.113.7")));
    assert!(!every_v4.trusts(ip("::1")));
}

#[test]
fn a_plain_v6_range_never_trusts_a_v4_peer() {
    let all_v6 = TrustedProxies::parse("::/0").unwrap();
    assert!(all_v6.trusts(ip("2001:db8::1")));
    assert!(!all_v6.trusts(ip("203.0.113.7")));
    assert!(!all_v6.trusts(ip("::ffff:203.0.113.7")));
    // Wider than the mapped /96: it names v6 space, not a v4 range.
    let wide = TrustedProxies::parse("::ffff:0:0/16").unwrap();
    assert!(wide.trusts(ip("::1")));
    assert!(!wide.trusts(ip("10.0.0.1")));
}

#[test]
fn a_non_ascii_hop_does_not_hide_the_hops_a_proxy_appended() {
    let proxies = TrustedProxies::parse("10.0.0.0/8").unwrap();
    let mut headers = HeaderMap::new();
    headers.append(
        X_FORWARDED_FOR,
        HeaderValue::from_bytes(b"caf\xc3\xa9, \xff, 203.0.113.7").unwrap(),
    );
    assert_eq!(
        proxies.client_ip(peer("10.0.0.5"), &headers),
        ip("203.0.113.7")
    );
    // Fail-safe: an unreadable hop a trusted proxy vouched for ends the
    // walk at that proxy rather than skipping past it.
    let mut headers = HeaderMap::new();
    headers.append(
        X_FORWARDED_FOR,
        HeaderValue::from_bytes(b"203.0.113.7, \xff").unwrap(),
    );
    assert_eq!(
        proxies.client_ip(peer("10.0.0.5"), &headers),
        ip("10.0.0.5")
    );
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
