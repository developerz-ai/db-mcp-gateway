//! `numeric`, rendered from its binary wire form the way Postgres prints it.
//!
//! The wire form is base-10000 digits, the position of the first one
//! (`weight`), a sign word and the display scale (`dscale`). Going through a
//! decimal type would lose the last of these — `1.50` would print as `1.5`
//! or `1.5000` — and has no value for `NaN` or the infinities. The text is
//! plain digits, never scientific notation, with exactly `dscale` digits
//! after the point.

use std::fmt::Write;

use super::json::RowWeight;
use super::wire::Refused;

const POSITIVE: u16 = 0x0000;
const NEGATIVE: u16 = 0x4000;
const NAN: u16 = 0xC000;
const INFINITY: u16 = 0xD000;
const NEGATIVE_INFINITY: u16 = 0xF000;
/// Decimal digits in one wire digit.
const GROUP: usize = 4;

/// The value's text. Charged to `weight` before it is built: `1e131071` is
/// ten bytes on the wire and 131 072 digits printed.
pub(super) fn numeric(wire: &[u8], weight: &mut RowWeight<'_>) -> Result<String, Refused> {
    let (header, digits) = wire.split_at_checked(8).ok_or(Refused::Undecodable)?;
    let word = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
    let (count, first_weight, sign, scale) = (word(0), word(2).cast_signed(), word(4), word(6));
    if digits.len() != usize::from(count) * 2 {
        return Err(Refused::Undecodable);
    }
    let negative = match sign {
        POSITIVE => false,
        NEGATIVE => true,
        NAN => return Ok("NaN".to_string()),
        INFINITY => return Ok("Infinity".to_string()),
        NEGATIVE_INFINITY => return Ok("-Infinity".to_string()),
        _ => return Err(Refused::Undecodable),
    };
    // The digit `index` places after the first; zero where none was sent.
    let digit = |index: i32| -> u16 {
        usize::try_from(index)
            .ok()
            .and_then(|at| digits.get(at * 2..at * 2 + 2))
            .map_or(0, |pair| u16::from_be_bytes([pair[0], pair[1]]))
    };
    let whole_groups = usize::try_from(i32::from(first_weight) + 1).unwrap_or(0);
    let scale = usize::from(scale);
    let longest = 1 + whole_groups.max(1) * GROUP + 1 + scale + GROUP;
    if !weight.charge(longest) {
        return Err(Refused::OverBudget);
    }

    let mut out = String::with_capacity(longest);
    if negative {
        out.push('-');
    }
    // Writing to a String is infallible.
    if first_weight < 0 {
        out.push('0');
    } else {
        let _ = write!(out, "{}", digit(0));
        for index in 1..=i32::from(first_weight) {
            let _ = write!(out, "{:04}", digit(index));
        }
    }
    if scale > 0 {
        out.push('.');
        let point = out.len();
        let mut index = i32::from(first_weight) + 1;
        while out.len() - point < scale {
            let _ = write!(out, "{:04}", digit(index));
            index += 1;
        }
        out.truncate(point + scale);
    }
    Ok(out)
}

/// `money`: an integer count of the currency's minor unit, `digits` of
/// which make one major unit — the `lc_monetary` the session ran under
/// decides how many, so they are asked of the server (see `run`). Plain
/// digits like a `numeric`, no currency symbol or grouping.
pub(super) fn money(minor: i64, digits: u8) -> String {
    let magnitude = minor.unsigned_abs().to_string();
    let digits = usize::from(digits);
    let sign = if minor < 0 { "-" } else { "" };
    if digits == 0 {
        return format!("{sign}{magnitude}");
    }
    let padded = format!("{magnitude:0>width$}", width = digits + 1);
    let (whole, fraction) = padded.split_at(padded.len() - digits);
    format!("{sign}{whole}.{fraction}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::budget::ResultBudget;

    /// A wire `numeric`: digits, weight, sign word, display scale.
    fn wire(digits: &[u16], weight: i16, sign: u16, scale: u16) -> Vec<u8> {
        let count = u16::try_from(digits.len()).expect("few digits");
        let mut out = Vec::new();
        out.extend(count.to_be_bytes());
        out.extend(weight.to_be_bytes());
        out.extend(sign.to_be_bytes());
        out.extend(scale.to_be_bytes());
        out.extend(digits.iter().flat_map(|d| d.to_be_bytes()));
        out
    }

    fn text(bytes: &[u8]) -> Result<String, Refused> {
        let budget = ResultBudget::new(1);
        numeric(bytes, &mut RowWeight::new(&budget))
    }

    #[test]
    fn prints_the_display_scale_and_nothing_else() {
        let cases = [
            (wire(&[1234, 5600], 0, POSITIVE, 4), "1234.5600"),
            (wire(&[1234, 5600], 0, POSITIVE, 2), "1234.56"),
            (wire(&[1, 5000], 0, NEGATIVE, 1), "-1.5"),
            (wire(&[1, 5000], 0, POSITIVE, 6), "1.500000"),
            (wire(&[], 0, POSITIVE, 0), "0"),
            (wire(&[], 0, POSITIVE, 3), "0.000"),
            (wire(&[5], -1, POSITIVE, 4), "0.0005"),
            (wire(&[1], -3, NEGATIVE, 12), "-0.000000000001"),
            (wire(&[12, 3400], 1, POSITIVE, 0), "123400"),
            (wire(&[1], 3, POSITIVE, 0), "1000000000000"),
            (wire(&[], 0, NAN, 0), "NaN"),
            (wire(&[], 0, INFINITY, 0), "Infinity"),
            (wire(&[], 0, NEGATIVE_INFINITY, 0), "-Infinity"),
        ];
        for (bytes, want) in cases {
            assert_eq!(text(&bytes).as_deref(), Ok(want), "{bytes:?}");
        }
    }

    #[test]
    fn a_value_too_long_for_the_budget_is_never_built() {
        // 1e131071: one digit on the wire.
        let huge = wire(&[1000], i16::MAX, POSITIVE, 0);
        let printed = text(&huge).expect("fits an empty budget");
        assert_eq!(printed.len(), 131_072);
        let budget = ResultBudget::new(1);
        let mut weight = RowWeight::new(&budget);
        let fill = crate::exec::adapter::MAX_RESULT_BYTES - 1_000;
        assert!(weight.charge(fill));
        assert_eq!(numeric(&huge, &mut weight), Err(Refused::OverBudget));
    }

    #[test]
    fn money_prints_its_minor_units_after_the_point() {
        assert_eq!(money(-1_234_567, 2), "-12345.67");
        assert_eq!(money(5, 2), "0.05");
        assert_eq!(money(0, 2), "0.00");
        assert_eq!(money(1_234, 0), "1234");
        assert_eq!(money(i64::MIN, 2), "-92233720368547758.08");
        assert_eq!(money(i64::MAX, 3), "9223372036854775.807");
    }

    #[test]
    fn malformed_wire_forms_are_refused() {
        assert_eq!(text(&[0, 1, 0, 0]), Err(Refused::Undecodable));
        assert_eq!(text(&wire(&[], 0, 0x8000, 0)), Err(Refused::Undecodable));
        let mut short = wire(&[1, 2], 0, POSITIVE, 0);
        short.pop();
        assert_eq!(text(&short), Err(Refused::Undecodable));
    }
}
