//! Text renderings for values JSON has no native form for.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde_json::Value;
use sqlx::postgres::types::PgInterval;
use sqlx::postgres::{PgValueFormat, PgValueRef};

/// Key of the marker object returned for a cell this gateway can't render.
const UNSUPPORTED_TYPE_KEY: &str = "unsupported_type";

/// The marker substituted for an unrenderable cell. Deliberately not null:
/// it says "this cell holds a value the gateway can't render".
pub(super) fn unsupported(type_name: &str) -> Value {
    Value::Object(serde_json::Map::from_iter([(
        UNSUPPORTED_TYPE_KEY.to_string(),
        Value::from(type_name),
    )]))
}

/// JSON numbers cannot be NaN or infinite; `serde_json` would turn them into
/// `null`, which here means SQL NULL. Postgres' own spellings instead.
pub(super) fn float(v: f64) -> Value {
    if v.is_nan() {
        Value::from("NaN")
    } else if v.is_infinite() {
        Value::from(if v > 0.0 { "Infinity" } else { "-Infinity" })
    } else {
        Value::from(v)
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::from("\\x"), |mut out, b| {
        // Writing to a String is infallible.
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// ISO-8601 duration. Postgres keeps months, days and microseconds apart
/// (a month is not a fixed number of days), so each is rendered on its own
/// and may carry its own sign, as Postgres' `iso_8601` interval style does.
pub(super) fn interval(v: &PgInterval) -> String {
    let mut out = String::from("P");
    let (years, months) = (v.months / 12, v.months % 12);
    for (n, unit) in [
        (i64::from(years), 'Y'),
        (i64::from(months), 'M'),
        (i64::from(v.days), 'D'),
    ] {
        if n != 0 {
            out.push_str(&format!("{n}{unit}"));
        }
    }
    let micros = v.microseconds;
    if micros != 0 {
        let (hours, rest) = (micros / 3_600_000_000, micros % 3_600_000_000);
        let (minutes, rest) = (rest / 60_000_000, rest % 60_000_000);
        out.push('T');
        if hours != 0 {
            out.push_str(&format!("{hours}H"));
        }
        if minutes != 0 {
            out.push_str(&format!("{minutes}M"));
        }
        if rest != 0 {
            out.push_str(&seconds(rest));
        }
    }
    if out == "P" {
        out.push_str("T0S");
    }
    out
}

fn seconds(micros: i64) -> String {
    let sign = if micros < 0 { "-" } else { "" };
    let micros = micros.unsigned_abs();
    let (whole, frac) = (micros / 1_000_000, micros % 1_000_000);
    if frac == 0 {
        format!("{sign}{whole}S")
    } else {
        let frac = format!("{frac:06}");
        format!("{sign}{whole}.{}S", frac.trim_end_matches('0'))
    }
}

/// `inet` / `cidr` without the `ipnetwork` feature: the binary wire form is
/// `family, bits, is_cidr, length, address bytes`. Text form passes through.
pub(super) fn inet(raw: &PgValueRef<'_>) -> Option<String> {
    if raw.format() == PgValueFormat::Text {
        return raw.as_str().ok().map(str::to_string);
    }
    let bytes = raw.as_bytes().ok()?;
    let (&[family, bits, is_cidr, len], addr) = bytes.split_first_chunk::<4>()?;
    if addr.len() != usize::from(len) {
        return None;
    }
    let (ip, full) = match family {
        2 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?).to_string(),
            32,
        ),
        3 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?).to_string(),
            128,
        ),
        _ => return None,
    };
    // Postgres prints the mask for every `cidr` and for an `inet` that is a
    // network rather than a single host.
    Some(if is_cidr != 0 || bits != full {
        format!("{ip}/{bits}")
    } else {
        ip
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_finite_floats_are_strings_not_null() {
        assert_eq!(float(f64::NAN), "NaN");
        assert_eq!(float(f64::INFINITY), "Infinity");
        assert_eq!(float(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(float(1.5), 1.5);
    }

    #[test]
    fn hex_is_backslash_x_prefixed() {
        assert_eq!(hex(&[0x00, 0x11, 0xff]), "\\x0011ff");
    }

    #[test]
    fn interval_renders_iso_8601() {
        let iv = |months, days, microseconds| {
            interval(&PgInterval {
                months,
                days,
                microseconds,
            })
        };
        assert_eq!(iv(14, 3, 14_706_000_000), "P1Y2M3DT4H5M6S");
        assert_eq!(iv(0, 0, 0), "PT0S");
        assert_eq!(iv(0, 0, 1_500_000), "PT1.5S");
        assert_eq!(iv(0, -1, -30_000_000), "P-1DT-30S");
        assert_eq!(iv(1, 0, 0), "P1M");
    }
}
