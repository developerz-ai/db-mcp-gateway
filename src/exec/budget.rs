//! Per-result budget: the row cap and the byte cap, charged row by row.
//!
//! Both adapters stop collecting the moment either runs out and flag the
//! result `truncated`; what happens to the rest of the statement is the
//! adapter's call (a read is cancelled, a write is drained and committed).

use serde_json::Value;

use super::adapter::MAX_RESULT_BYTES;

#[derive(Debug)]
pub(crate) struct ResultBudget {
    rows_left: usize,
    bytes_left: usize,
}

impl ResultBudget {
    pub(crate) fn new(row_limit: u32) -> Self {
        Self::with_bytes(row_limit, MAX_RESULT_BYTES)
    }

    fn with_bytes(row_limit: u32, bytes: usize) -> Self {
        Self {
            rows_left: usize::try_from(row_limit).unwrap_or(usize::MAX),
            bytes_left: bytes,
        }
    }

    /// Whether another row may still be collected. Checked before decoding
    /// so the row past the cap is never decoded.
    pub(crate) fn has_row_left(&self) -> bool {
        self.rows_left > 0
    }

    /// Whether a row of `wire_len` undecoded bytes can still fit. Asked
    /// before decoding: a row whose wire form alone is past what is left is
    /// never copied out of the driver's buffer.
    pub(crate) fn fits_wire(&self, wire_len: usize) -> bool {
        wire_len <= self.bytes_left
    }

    /// Charge `row` against the budget. `false` means it does not fit and
    /// must not be returned; the budget is left unchanged.
    pub(crate) fn admit(&mut self, row: &[Value]) -> bool {
        let size = row.iter().map(value_size).sum::<usize>();
        if !self.has_row_left() || size > self.bytes_left {
            return false;
        }
        self.rows_left -= 1;
        self.bytes_left -= size;
        true
    }
}

/// What a decoded value holds in memory: every node is a whole [`Value`]
/// (an array of small numbers weighs several times its wire form), plus the
/// bytes of each string and key.
fn value_size(value: &Value) -> usize {
    const NODE: usize = size_of::<Value>();
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => NODE,
        Value::String(s) => NODE + s.len(),
        Value::Array(items) => NODE + items.iter().map(value_size).sum::<usize>(),
        Value::Object(map) => {
            NODE + map
                .iter()
                .map(|(k, v)| size_of::<String>() + k.len() + value_size(v))
                .sum::<usize>()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn row_cap_runs_out_first() {
        let mut b = ResultBudget::with_bytes(2, 1_000);
        assert!(b.admit(&[json!(1)]));
        assert!(b.admit(&[json!(2)]));
        assert!(!b.has_row_left());
        assert!(!b.admit(&[json!(3)]));
    }

    #[test]
    fn byte_cap_rejects_the_row_that_would_overflow() {
        const NODE: usize = size_of::<Value>();
        let mut b = ResultBudget::with_bytes(100, 2 * NODE + 30);
        assert!(b.admit(&[json!("0123456789")])); // leaves NODE + 20
        assert!(!b.admit(&[json!("012345678901234567890")])); // NODE + 21
        // A smaller row still fits: the failed admit charged nothing.
        assert!(b.admit(&[json!("01234567890123456789")])); // NODE + 20
    }

    #[test]
    fn every_node_weighs_a_whole_value() {
        let numbers = value_size(&json!([1, 2, 3, 4]));
        assert_eq!(numbers, 5 * size_of::<Value>());
    }

    #[test]
    fn a_row_past_the_budget_on_the_wire_does_not_fit() {
        let mut b = ResultBudget::with_bytes(10, 200);
        assert!(b.fits_wire(200));
        assert!(!b.fits_wire(201));
        assert!(b.admit(&[json!("0123456789")]));
        assert!(!b.fits_wire(200));
    }

    #[test]
    fn nested_values_are_weighed() {
        let flat = value_size(&json!("abcd"));
        let nested = value_size(&json!({"k": ["abcd", {"kk": "abcd"}]}));
        assert!(nested > 2 * flat, "{nested} vs {flat}");
    }

    #[test]
    fn zero_row_limit_admits_nothing() {
        let mut b = ResultBudget::new(0);
        assert!(!b.has_row_left());
        assert!(!b.admit(&[]));
    }
}
