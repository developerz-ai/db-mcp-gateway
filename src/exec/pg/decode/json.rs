//! `json` / `jsonb` cells, parsed against what the result budget has left.
//!
//! A JSON cell of small scalars decodes to many times its wire size — every
//! node is a whole [`Value`] — so a cell that passes the wire check can
//! still be far past the byte cap. Weighing it after `serde_json` built the
//! tree would be too late: the allocation is the harm. The tree is built by
//! a visitor that charges each node as it is read and stops the parse at the
//! first one that does not fit.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::exec::budget::ResultBudget;

/// Decoded bytes one row's JSON cells have claimed, against what the result
/// budget has left. Weighed the way [`ResultBudget::admit`] weighs the
/// finished row, so a row that parses to the end is one `admit` can judge.
#[derive(Debug)]
pub(in crate::exec::pg) struct RowWeight<'b> {
    budget: &'b ResultBudget,
    used: usize,
}

impl<'b> RowWeight<'b> {
    pub(in crate::exec::pg) fn new(budget: &'b ResultBudget) -> Self {
        Self { budget, used: 0 }
    }

    /// Claim `bytes` more; `false` once the row no longer fits.
    fn charge(&mut self, bytes: usize) -> bool {
        self.used = self.used.saturating_add(bytes);
        self.fits()
    }

    fn fits(&self) -> bool {
        self.budget.fits_wire(self.used)
    }
}

/// How one JSON cell parsed.
#[derive(Debug, PartialEq)]
pub(super) enum JsonCell {
    Value(Value),
    /// The parse stopped: the row cannot fit what the budget has left.
    OverBudget,
    Invalid,
}

pub(super) fn parse(text: &[u8], weight: &mut RowWeight<'_>) -> JsonCell {
    let mut de = serde_json::Deserializer::from_slice(text);
    let parsed = Budgeted(weight)
        .deserialize(&mut de)
        .and_then(|value| de.end().map(|()| value));
    match parsed {
        Ok(value) => JsonCell::Value(value),
        Err(_) if !weight.fits() => JsonCell::OverBudget,
        Err(_) => JsonCell::Invalid,
    }
}

/// Builds a [`Value`], charging every node before it is kept.
struct Budgeted<'w, 'b>(&'w mut RowWeight<'b>);

impl Budgeted<'_, '_> {
    /// One node plus `extra` bytes it owns (a string's text).
    fn node<E: Error>(&mut self, extra: usize) -> Result<(), E> {
        self.claim(size_of::<Value>().saturating_add(extra))
    }

    fn claim<E: Error>(&mut self, bytes: usize) -> Result<(), E> {
        if self.0.charge(bytes) {
            Ok(())
        } else {
            Err(E::custom("result budget exhausted"))
        }
    }
}

impl<'de> DeserializeSeed<'de> for Budgeted<'_, '_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Budgeted<'_, '_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: Error>(mut self, v: bool) -> Result<Value, E> {
        self.node(0)?;
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: Error>(mut self, v: i64) -> Result<Value, E> {
        self.node(0)?;
        Ok(Value::from(v))
    }

    fn visit_u64<E: Error>(mut self, v: u64) -> Result<Value, E> {
        self.node(0)?;
        Ok(Value::from(v))
    }

    fn visit_f64<E: Error>(mut self, v: f64) -> Result<Value, E> {
        self.node(0)?;
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E: Error>(mut self, v: &str) -> Result<Value, E> {
        self.node(v.len())?;
        Ok(Value::String(v.to_owned()))
    }

    fn visit_unit<E: Error>(mut self) -> Result<Value, E> {
        self.node(0)?;
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<Value, A::Error> {
        self.node(0)?;
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Budgeted(&mut *self.0))? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut entries: A) -> Result<Value, A::Error> {
        self.node(0)?;
        let mut map = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            self.claim(size_of::<String>().saturating_add(key.len()))?;
            let value = entries.next_value_seed(Budgeted(&mut *self.0))?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::exec::adapter::MAX_RESULT_BYTES;

    #[test]
    fn a_cell_that_fits_parses_like_serde_json() {
        let text = br#"{"b": [1, -2, 3.5, "x\ny", null, true], "a": {"k": 18446744073709551615}}"#;
        let budget = ResultBudget::new(10);
        let mut weight = RowWeight::new(&budget);
        let want: Value = serde_json::from_slice(text).expect("valid JSON");
        let JsonCell::Value(parsed) = parse(text, &mut weight) else {
            panic!("a small cell fits");
        };
        // Compared as text: key order is the document's, and `Value`
        // equality would not see a reordering.
        assert_eq!(parsed.to_string(), want.to_string());
        // Charged exactly what `admit` will weigh.
        let nodes = 10 * size_of::<Value>();
        let keys = 3 * (size_of::<String>() + 1);
        assert_eq!(weight.used, nodes + keys + "x\ny".len());
    }

    #[test]
    fn the_parse_stops_at_the_node_that_does_not_fit() {
        // 4 MB on the wire — inside the byte cap — and 64 MB decoded.
        let elements = 2 * MAX_RESULT_BYTES / size_of::<Value>();
        let text = format!("[{}0]", "0,".repeat(elements - 1));
        assert!(text.len() < MAX_RESULT_BYTES);
        let budget = ResultBudget::new(10);
        let mut weight = RowWeight::new(&budget);
        assert_eq!(parse(text.as_bytes(), &mut weight), JsonCell::OverBudget);
        assert!(
            weight.used <= MAX_RESULT_BYTES + size_of::<Value>(),
            "parsed on past the budget: {} bytes",
            weight.used
        );
    }

    #[test]
    fn malformed_text_is_invalid_not_over_budget() {
        let budget = ResultBudget::new(10);
        for text in [&b"[1, 2"[..], b"{} trailing", b""] {
            let mut weight = RowWeight::new(&budget);
            assert_eq!(parse(text, &mut weight), JsonCell::Invalid, "{text:?}");
        }
        let mut weight = RowWeight::new(&budget);
        assert_eq!(parse(b"7", &mut weight), JsonCell::Value(json!(7)));
    }
}
