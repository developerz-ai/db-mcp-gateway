//! The gateway limits the advertised text quotes (`tools/list` descriptions,
//! `initialize` instructions), read from the constants that enforce them so
//! the text cannot drift from the behaviour.

use crate::exec::{DEFAULT_STATEMENT_TIMEOUT_MS, MAX_RESULT_BYTES};
use crate::tools::GATEWAY_ROW_LIMIT_CEILING;

// Mirrors of `tools::run_query::DEFAULT_ROW_LIMIT` and
// `tools::sample_table::DEFAULT_SAMPLE_LIMIT`, which are private to their
// tools; replace with imports once those are `pub(crate)`.
const RUN_QUERY_DEFAULT_ROWS: u32 = 1000;
const SAMPLE_TABLE_DEFAULT_ROWS: u32 = 10;

const MIB: usize = 1024 * 1024;

/// `run_query`'s row limit when neither the caller nor the grant sets one.
pub(super) fn run_query_default_rows() -> String {
    grouped(RUN_QUERY_DEFAULT_ROWS)
}

/// `sample_table`'s row limit when neither the caller nor the grant sets one.
pub(super) fn sample_default_rows() -> String {
    grouped(SAMPLE_TABLE_DEFAULT_ROWS)
}

/// The gateway-wide row ceiling no `limit` or grant can exceed.
pub(super) fn row_ceiling() -> String {
    grouped(GATEWAY_ROW_LIMIT_CEILING)
}

/// The per-call result byte cap, e.g. `32 MiB`.
pub(super) fn result_cap() -> String {
    format!("{} MiB", MAX_RESULT_BYTES / MIB)
}

/// The statement-timeout ceiling, e.g. `30 s`.
pub(super) fn timeout_ceiling() -> String {
    format!("{} s", DEFAULT_STATEMENT_TIMEOUT_MS / 1000)
}

/// `100000` → `100,000`: the form the spec and an agent read numbers in.
fn grouped(n: u32) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_inserts_thousands_separators() {
        assert_eq!(grouped(10), "10");
        assert_eq!(grouped(1000), "1,000");
        assert_eq!(grouped(100_000), "100,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    #[test]
    fn caps_render_in_whole_units() {
        assert!(
            MAX_RESULT_BYTES.is_multiple_of(MIB),
            "byte cap is whole MiB"
        );
        assert!(
            DEFAULT_STATEMENT_TIMEOUT_MS.is_multiple_of(1000),
            "timeout is whole s"
        );
    }
}
