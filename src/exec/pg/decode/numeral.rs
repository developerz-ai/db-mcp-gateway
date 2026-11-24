//! The numerals of a JSON text, and whether an `f64` holds one exactly.
//!
//! `serde_json` hands a number that is not a 64-bit integer to its visitor
//! as an `f64`, and the digits it could not hold are gone: a `jsonb` number
//! is a `numeric`, so `12345678901234567890.123` would come back as
//! `12345678901234567000`. The visitor cannot ask the parser for the text it
//! read, so the text is found again here: numbers are visited in document
//! order, and so is this cursor.

/// A cursor over the number tokens of one JSON text, in document order.
#[derive(Debug)]
pub(super) struct Numerals<'t> {
    text: &'t [u8],
    at: usize,
    /// Numbers visited whose text nobody asked for: integers, mostly, so a
    /// document without a fraction or an exponent is never scanned twice.
    unread: usize,
}

impl<'t> Numerals<'t> {
    pub(super) fn new(text: &'t [u8]) -> Self {
        Self {
            text,
            at: 0,
            unread: 0,
        }
    }

    /// The parser visited a number whose text is not needed.
    pub(super) fn skip(&mut self) {
        self.unread += 1;
    }

    /// The text of the number the parser is visiting now.
    pub(super) fn current(&mut self) -> Option<&'t str> {
        for _ in 0..self.unread {
            self.next_token()?;
        }
        self.unread = 0;
        self.next_token()
    }

    fn next_token(&mut self) -> Option<&'t str> {
        let (start, end) = self.next_span()?;
        std::str::from_utf8(&self.text[start..end]).ok()
    }

    /// Outside a string, only a number starts with a digit or a minus sign.
    fn next_span(&mut self) -> Option<(usize, usize)> {
        while let Some(&byte) = self.text.get(self.at) {
            match byte {
                b'"' => self.skip_string(),
                b'-' | b'0'..=b'9' => {
                    let start = self.at;
                    let rest = &self.text[start..];
                    let len = rest
                        .iter()
                        .position(|b| !matches!(b, b'0'..=b'9' | b'+' | b'-' | b'.' | b'e' | b'E'))
                        .unwrap_or(rest.len());
                    self.at += len;
                    return Some((start, start + len));
                }
                _ => self.at += 1,
            }
        }
        None
    }

    fn skip_string(&mut self) {
        self.at += 1;
        while let Some(&byte) = self.text.get(self.at) {
            // An escape is two bytes; the one after `\` never ends the string.
            self.at += if byte == b'\\' { 2 } else { 1 };
            if byte == b'"' {
                return;
            }
        }
    }
}

/// `text` with every number token past `f64`'s range (`1e400`; `serde_json`
/// refuses those outright) turned into a string of its numeral — what the
/// visitor keeps for any number an `f64` cannot hold. `None` when there is
/// none, the common case: nothing is copied.
pub(super) fn quote_out_of_range(text: &[u8]) -> Option<Vec<u8>> {
    let mut numerals = Numerals::new(text);
    let mut quoted: Option<Vec<u8>> = None;
    let mut copied = 0;
    while let Some((start, end)) = numerals.next_span() {
        let finite = std::str::from_utf8(&text[start..end])
            .ok()
            .and_then(|numeral| numeral.parse::<f64>().ok())
            .is_none_or(f64::is_finite);
        if finite {
            continue;
        }
        let out = quoted.get_or_insert_with(|| Vec::with_capacity(text.len() + 2));
        out.extend_from_slice(&text[copied..start]);
        out.push(b'"');
        out.extend_from_slice(&text[start..end]);
        out.push(b'"');
        copied = end;
    }
    let mut out = quoted?;
    out.extend_from_slice(&text[copied..]);
    Some(out)
}

/// Whether two JSON numerals name the same number: `1.10`, `11e-1` and `1.1`
/// do. Compared as digits and a power of ten — never through a float.
pub(super) fn same_number(a: &str, b: &str) -> bool {
    match (Decimal::parse(a), Decimal::parse(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// `±digits × 10^exponent`, `digits` without leading or trailing zeros.
/// Zero is the empty digit string, whatever its sign or exponent.
#[derive(Debug, PartialEq, Eq)]
struct Decimal {
    negative: bool,
    digits: String,
    exponent: i64,
}

impl Decimal {
    fn parse(numeral: &str) -> Option<Self> {
        let (negative, rest) = match numeral.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, numeral),
        };
        let (mantissa, exponent) = match rest.split_once(['e', 'E']) {
            Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().ok()?),
            None => (rest, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let mut digits = format!("{whole}{fraction}");
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let significant = digits.trim_end_matches('0').len();
        let dropped = i64::try_from(digits.len() - significant).ok()?;
        let exponent = exponent
            .checked_sub(i64::try_from(fraction.len()).ok()?)?
            .checked_add(dropped)?;
        digits.truncate(significant);
        let digits = digits.trim_start_matches('0').to_string();
        if digits.is_empty() {
            return Some(Self {
                negative: false,
                digits,
                exponent: 0,
            });
        }
        Some(Self {
            negative,
            digits,
            exponent,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numerals_are_compared_by_value() {
        for (a, b) in [
            ("1.10", "1.1"),
            ("11e-1", "1.1"),
            ("1E2", "100"),
            ("1e+2", "100.0"),
            ("-0.0", "0"),
            ("0e99", "0.00"),
            ("0.5", "5e-1"),
            ("1e30", "1000000000000000000000000000000"),
        ] {
            assert!(same_number(a, b), "{a} = {b}");
        }
        for (a, b) in [
            ("1.1", "1.10000000000000000001"),
            ("18446744073709551616", "18446744073709552000"),
            ("1", "-1"),
            ("1e2", "1e3"),
            ("1", "x"),
            ("", "0"),
        ] {
            assert!(!same_number(a, b), "{a} != {b}");
        }
    }

    #[test]
    fn the_cursor_finds_numbers_outside_strings_only() {
        let text = br#"{"k1": -1.5e3, "a\"2": ["3", 4, true, null, 5E-2], "e": 6}"#;
        let mut numerals = Numerals::new(text);
        assert_eq!(numerals.current(), Some("-1.5e3"));
        numerals.skip(); // 4
        assert_eq!(numerals.current(), Some("5E-2"));
        assert_eq!(numerals.current(), Some("6"));
        assert_eq!(numerals.current(), None);
    }

    #[test]
    fn a_string_cut_short_ends_the_scan() {
        let mut numerals = Numerals::new(br#"["1\"#);
        assert_eq!(numerals.current(), None);
    }
}
