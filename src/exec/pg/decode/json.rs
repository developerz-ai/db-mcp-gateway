//! `json` / `jsonb` cells, parsed against what the result budget has left.
//!
//! A JSON cell of small scalars decodes to many times its wire size — every
//! node is a whole [`Value`] — so a cell that passes the wire check can
//! still be far past the byte cap. Weighing it after `serde_json` built the
//! tree would be too late: the allocation is the harm. The tree is built by
//! a visitor that charges each node as it is read and stops the parse at the
//! first one that does not fit.
//!
//! Numbers keep their value. One that is not a 64-bit integer reaches the
//! visitor as an `f64`; when that `f64` is not the number the document
//! spells — a `jsonb` number is a `numeric` — the cell carries the numeral
//! as a string instead, the way a `numeric` column does.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::exec::budget::ResultBudget;

use super::numeral::{Numerals, same_number};

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
    pub(super) fn charge(&mut self, bytes: usize) -> bool {
        self.used = self.used.saturating_add(bytes);
        self.fits()
    }

    /// Give back what a value that was dropped again had claimed.
    fn refund(&mut self, bytes: usize) {
        self.used = self.used.saturating_sub(bytes);
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
    let mut numerals = Numerals::new(text);
    let parsed = Budgeted {
        weight,
        numerals: &mut numerals,
    }
    .deserialize(&mut de)
    .and_then(|value| de.end().map(|()| value));
    match parsed {
        Ok(value) => JsonCell::Value(value),
        Err(_) if !weight.fits() => JsonCell::OverBudget,
        Err(_) => JsonCell::Invalid,
    }
}

/// Builds a [`Value`], charging every node before it is kept.
struct Budgeted<'w, 'b, 't> {
    weight: &'w mut RowWeight<'b>,
    numerals: &'w mut Numerals<'t>,
}

impl<'b, 't> Budgeted<'_, 'b, 't> {
    /// The same visitor for a value nested in this one.
    fn nested(&mut self) -> Budgeted<'_, 'b, 't> {
        Budgeted {
            weight: self.weight,
            numerals: self.numerals,
        }
    }

    /// One node plus `extra` bytes it owns (a string's text).
    fn node<E: Error>(&mut self, extra: usize) -> Result<(), E> {
        self.claim(size_of::<Value>().saturating_add(extra))
    }

    fn claim<E: Error>(&mut self, bytes: usize) -> Result<(), E> {
        if self.weight.charge(bytes) {
            Ok(())
        } else {
            Err(E::custom("result budget exhausted"))
        }
    }
}

impl<'de> DeserializeSeed<'de> for Budgeted<'_, '_, '_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Budgeted<'_, '_, '_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: Error>(mut self, v: bool) -> Result<Value, E> {
        self.node(0)?;
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: Error>(mut self, v: i64) -> Result<Value, E> {
        self.numerals.skip();
        self.node(0)?;
        Ok(Value::from(v))
    }

    fn visit_u64<E: Error>(mut self, v: u64) -> Result<Value, E> {
        self.numerals.skip();
        self.node(0)?;
        Ok(Value::from(v))
    }

    fn visit_f64<E: Error>(mut self, v: f64) -> Result<Value, E> {
        let numeral = self
            .numerals
            .current()
            .ok_or_else(|| E::custom("number without a numeral"))?;
        match Number::from_f64(v) {
            Some(number) if same_number(numeral, &number.to_string()) => {
                self.node(0)?;
                Ok(Value::Number(number))
            }
            _ => {
                self.node(numeral.len())?;
                Ok(Value::String(numeral.to_owned()))
            }
        }
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
        while let Some(item) = seq.next_element_seed(self.nested())? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut entries: A) -> Result<Value, A::Error> {
        self.node(0)?;
        let mut map = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            // `json` keeps duplicate keys and the map only the last value, in
            // the first one's position (`Map::insert`, as `serde_json` does).
            // The replaced value is released before its replacement is read,
            // so the two are never charged at once.
            if let Some(slot) = map.get_mut(&key) {
                let replaced = std::mem::take(slot);
                self.weight.refund(claimed_by(&replaced));
                drop(replaced);
                *slot = entries.next_value_seed(self.nested())?;
                continue;
            }
            self.claim(size_of::<String>().saturating_add(key.len()))?;
            let value = entries.next_value_seed(self.nested())?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

/// What parsing `value` claimed: the weights [`Budgeted`] charges, summed.
fn claimed_by(value: &Value) -> usize {
    let node = size_of::<Value>();
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => node,
        Value::String(text) => node + text.len(),
        Value::Array(items) => node + items.iter().map(claimed_by).sum::<usize>(),
        Value::Object(map) => {
            let entries = map
                .iter()
                .map(|(key, value)| size_of::<String>() + key.len() + claimed_by(value));
            node + entries.sum::<usize>()
        }
    }
}

#[cfg(test)]
mod tests;
