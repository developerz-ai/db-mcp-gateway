//! `tls_cert_not_after_timestamp`: when the served certificate expires. Read
//! from the leaf (first) certificate of the PEM chain with a minimal DER walk
//! to `tbsCertificate.validity.notAfter` — the one field needed does not
//! justify an X.509 dependency.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::NaiveDateTime;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";
const SEQUENCE: u8 = 0x30;
const EXPLICIT_VERSION: u8 = 0xa0;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CertError {
    #[error("certificate file unreadable: {0}")]
    Read(#[from] std::io::Error),
    #[error("no PEM certificate block")]
    NoCertificate,
    #[error("PEM certificate is not valid base64")]
    Base64,
    #[error("certificate DER is malformed")]
    Der,
}

/// Unix seconds of the leaf certificate's `notAfter`.
pub(crate) async fn not_after(cert_path: &Path) -> Result<i64, CertError> {
    let pem = tokio::fs::read_to_string(cert_path).await?;
    not_after_of_pem(&pem)
}

pub(crate) fn not_after_of_pem(pem: &str) -> Result<i64, CertError> {
    let (_, rest) = pem.split_once(BEGIN).ok_or(CertError::NoCertificate)?;
    let (body, _) = rest.split_once(END).ok_or(CertError::NoCertificate)?;
    let b64: String = body.split_whitespace().collect();
    let der = STANDARD.decode(b64).map_err(|_| CertError::Base64)?;
    not_after_of_der(&der).ok_or(CertError::Der)
}

fn not_after_of_der(der: &[u8]) -> Option<i64> {
    let (cert, _) = expect(der, SEQUENCE)?;
    let (mut tbs, _) = expect(cert, SEQUENCE)?;
    if tbs.first() == Some(&EXPLICIT_VERSION) {
        tbs = tlv(tbs)?.2;
    }
    // serialNumber, signature, issuer: skipped whole.
    for _ in 0..3 {
        tbs = tlv(tbs)?.2;
    }
    let (validity, _) = expect(tbs, SEQUENCE)?;
    let (_, _, after_not_before) = tlv(validity)?;
    let (tag, time, _) = tlv(after_not_before)?;
    parse_time(tag, std::str::from_utf8(time).ok()?)
}

/// `(tag, content, rest)` of the DER element at the start of `buf`.
fn tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, buf) = buf.split_first()?;
    let (&first, mut buf) = buf.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let width = usize::from(first & 0x7f);
        if width == 0 || width > 4 || buf.len() < width {
            return None;
        }
        let (bytes, rest) = buf.split_at(width);
        buf = rest;
        bytes
            .iter()
            .fold(0usize, |len, &b| (len << 8) | usize::from(b))
    };
    if buf.len() < len {
        return None;
    }
    let (content, rest) = buf.split_at(len);
    Some((tag, content, rest))
}

fn expect(buf: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (found, content, rest) = tlv(buf)?;
    (found == tag).then_some((content, rest))
}

/// RFC 5280 §4.1.2.5: UTCTime years 50–99 are 19xx, 00–49 are 20xx.
fn parse_time(tag: u8, time: &str) -> Option<i64> {
    let full = match tag {
        UTC_TIME => {
            let yy: u32 = time.get(..2)?.parse().ok()?;
            let century = if yy >= 50 { "19" } else { "20" };
            format!("{century}{time}")
        }
        GENERALIZED_TIME => time.to_owned(),
        _ => return None,
    };
    let parsed = NaiveDateTime::parse_from_str(full.strip_suffix('Z')?, "%Y%m%d%H%M%S").ok()?;
    Some(parsed.and_utc().timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_not_after_of_a_generated_certificate() {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2031, 7, 9);
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();

        let expected = chrono::NaiveDate::from_ymd_opt(2031, 7, 9)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .unwrap()
            .and_utc()
            .timestamp();
        assert_eq!(not_after_of_pem(&pem).unwrap(), expected);
    }

    #[test]
    fn utc_time_before_2050_is_this_century() {
        assert_eq!(parse_time(UTC_TIME, "491231235959Z"), Some(2_524_607_999));
        assert_eq!(parse_time(UTC_TIME, "500101000000Z"), Some(-631_152_000));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(matches!(
            not_after_of_pem("nothing"),
            Err(CertError::NoCertificate)
        ));
        let truncated = format!("{BEGIN}\nMIIB\n{END}");
        assert!(not_after_of_pem(&truncated).is_err());
        assert_eq!(tlv(&[0x30, 0x85, 1, 2, 3, 4, 5]), None);
    }
}
