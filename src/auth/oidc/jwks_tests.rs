use super::*;

const RSA_N: &str = "2AQ0bUWQjkkFpAcacf2JwKfyMo2v4g-wiNHS6o1CWoxTgqGCve0vjZ68r-6d-Vz60igrdzKe1CkkX2sSsRdnaJCz8W0x4zreERYKn8n8wDWaxSivBqhzk2krT7Zcsb7-1hn35OG133DVIWfpRXSQDuySsqt2aMZ-hhGc_YAQQn293b-pr69db8bOhB19GepYoyRQlEFgH2zRKvo-bxNViTLtou21YQR6xVJBqUTZvF-0YQWDghC9Q3EXRSn-eNnWgCtWoxgYg1VJI8En-qu3vtGrTmycqS-yj3kYeTmLOGChrjMQflU83KculsuUKvZq61kogU-BhWCXqG0aBJgMdQ";
// RFC 7515 Appendix A.3 P-256 public key.
const EC_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const EC_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

fn rsa(kid: &str, alg: Option<&str>) -> Jwk {
    Jwk {
        kid: Some(kid.into()),
        kty: "RSA".into(),
        use_: Some("sig".into()),
        alg: alg.map(str::to_string),
        n: Some(RSA_N.into()),
        e: Some("AQAB".into()),
        crv: None,
        x: None,
        y: None,
    }
}

fn ec(kid: &str, crv: &str) -> Jwk {
    Jwk {
        kid: Some(kid.into()),
        kty: "EC".into(),
        use_: None,
        alg: None,
        n: None,
        e: None,
        crv: Some(crv.into()),
        x: Some(EC_X.into()),
        y: Some(EC_Y.into()),
    }
}

fn cache(keys: Vec<Jwk>) -> JwksCache {
    JwksCache::new(Jwks { keys })
}

#[test]
fn rsa_key_without_alg_verifies_rs256_and_ps256_only() {
    let key = cache(vec![rsa("k", None)]).get("k").expect("rsa key kept");
    assert!(key.for_alg(Algorithm::RS256).is_some());
    assert!(key.for_alg(Algorithm::PS256).is_some());
    assert!(key.for_alg(Algorithm::ES256).is_none());
    assert!(key.for_alg(Algorithm::HS256).is_none());
}

#[test]
fn declared_alg_narrows_the_key() {
    let key = cache(vec![rsa("k", Some("RS256"))]).get("k").expect("kept");
    assert!(key.for_alg(Algorithm::RS256).is_some());
    assert!(key.for_alg(Algorithm::PS256).is_none());
}

#[test]
fn declared_alg_outside_the_family_drops_the_key() {
    assert!(cache(vec![rsa("k", Some("HS256"))]).get("k").is_none());
    assert!(cache(vec![rsa("k", Some("ES256"))]).get("k").is_none());
}

#[test]
fn p256_key_verifies_es256_only() {
    let key = cache(vec![ec("e", "P-256")]).get("e").expect("ec key kept");
    assert!(key.for_alg(Algorithm::ES256).is_some());
    assert!(key.for_alg(Algorithm::RS256).is_none());
}

#[test]
fn unsupported_curve_and_encryption_keys_are_skipped() {
    let mut enc = rsa("enc", None);
    enc.use_ = Some("enc".into());
    let keys = cache(vec![ec("p384", "P-384"), enc]);
    assert!(keys.get("p384").is_none());
    assert!(keys.get("enc").is_none());
}

#[test]
fn probe_hits_known_kid_and_rate_limits_unknown_kid() {
    let fresh = cache(vec![rsa("k", None)]);
    assert!(matches!(probe(Some(&fresh), "k"), Probe::Hit(_)));
    assert!(matches!(probe(Some(&fresh), "other"), Probe::Unknown));
    assert!(matches!(probe(None, "k"), Probe::Fetch));
}

#[test]
fn unknown_kid_refetches_after_the_window_and_known_kid_after_the_ttl() {
    let key = cache(vec![rsa("k", None)]).get("k");
    assert!(matches!(classify(None, UNKNOWN_KID_REFETCH), Probe::Fetch));
    assert!(matches!(
        classify(key.clone(), UNKNOWN_KID_REFETCH),
        Probe::Hit(_)
    ));
    assert!(matches!(classify(key, JWKS_TTL), Probe::Fetch));
}
