//! Row → JSON decoding.
//!
//! The decoder for each column is chosen once, from the column's type, when
//! the first row arrives ([`decoders`]); every cell after that is one `match`
//! and one decode. The old per-cell probe chain tried up to fifteen decodes
//! and allocated the type name for every cell.
//!
//! The cardinal rule is that `Value::Null` means *SQL NULL* and nothing else.
//! A type this gateway can't render — or a value that fails to decode —
//! becomes `{"unsupported_type": "<pg type>"}` instead: an agent acting on
//! query results must never be handed a null that was really a `uuid`, a
//! `timestamptz`, or a money `numeric` (#136).

mod datetime;
mod json;
mod numeral;
mod numeric;
mod render;
mod wire;

use serde_json::Value;
use sqlx::postgres::{PgRow, PgTypeInfo, PgTypeKind, PgValueFormat, PgValueRef, Postgres};
use sqlx::{Row, Type, TypeInfo, ValueRef};

use json::JsonCell;
pub(super) use json::RowWeight;
use render::unsupported;
use wire::{Refused, Scalar};

const MONEY: u32 = 790;

/// A row whose decoded form cannot fit what the result budget has left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OverBudget;

/// How to turn one column's cells into JSON. Variants follow the rendering
/// contract in `website/docs/initial-idea/03-mcp-tools.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ColumnDecoder {
    Json,
    /// Sent as a version byte, then the same text as `json`.
    Jsonb,
    Scalar(Scalar),
    /// A one-dimensional array: a JSON array whose items may be `null`.
    Array(Scalar),
    /// Ranges, PostGIS, composites …: the marker names the type so
    /// the caller can cast it (`SELECT my_col::text`).
    Unsupported(String),
}

impl ColumnDecoder {
    /// `money_digits`: how many digits of a `money` value are its fraction,
    /// in the session that sent it.
    pub(super) fn for_type(ty: &PgTypeInfo, money_digits: u8) -> Self {
        match ty.oid().map(|oid| oid.0) {
            Some(114) => return Self::Json,
            Some(3802) => return Self::Jsonb,
            _ => {}
        }
        if let Some(scalar) = scalar_for(ty, money_digits) {
            return Self::Scalar(scalar);
        }
        match ty.kind() {
            // A domain is sent in its base type's format.
            PgTypeKind::Domain(base) => Self::for_type(base, money_digits),
            PgTypeKind::Array(element) => match scalar_for(element, money_digits) {
                Some(scalar) => Self::Array(scalar),
                None => Self::Unsupported(ty.name().to_string()),
            },
            _ => Self::Unsupported(ty.name().to_string()),
        }
    }

    fn decode(
        &self,
        row: &PgRow,
        idx: usize,
        weight: &mut RowWeight<'_>,
    ) -> Result<Value, OverBudget> {
        let Ok(raw) = row.try_get_raw(idx) else {
            // Unreachable: `idx` comes from this row's own column list.
            return Ok(unsupported("unknown"));
        };
        // Type-agnostic NULL check first: NULL has no bytes to decode.
        if raw.is_null() {
            return Ok(Value::Null);
        }
        let decoded = match (self, wire_bytes(&raw)) {
            (Self::Unsupported(name), _) => return Ok(unsupported(name)),
            (_, None) => Err(Refused::Undecodable),
            (Self::Json, Some(text)) => json_cell(text, weight),
            // Version 1 is the only `jsonb` wire version there is.
            (Self::Jsonb, Some(wire)) => match wire.strip_prefix(&[1]) {
                Some(text) => json_cell(text, weight),
                None => Err(Refused::Undecodable),
            },
            (Self::Scalar(scalar), Some(wire)) => scalar.decode(wire, weight),
            (Self::Array(element), Some(wire)) => wire::array(*element, wire, weight),
        };
        match decoded {
            Ok(value) => Ok(value),
            Err(Refused::OverBudget) => Err(OverBudget),
            Err(Refused::Undecodable) => Ok(unsupported(raw.type_info().name())),
        }
    }
}

/// The decoder for a type sent as one value: a built-in by its OID, an enum
/// or a text-like extension type (`citext`) as text, a domain as its base.
fn scalar_for(ty: &PgTypeInfo, money_digits: u8) -> Option<Scalar> {
    match ty.oid().map(|oid| oid.0) {
        Some(MONEY) => return Some(Scalar::Money(money_digits)),
        Some(oid) => {
            if let Some(scalar) = Scalar::for_oid(oid) {
                return Some(scalar);
            }
        }
        None => {}
    }
    match ty.kind() {
        // An enum's binary form is its label's UTF-8 bytes.
        PgTypeKind::Enum(_) => Some(Scalar::Text),
        PgTypeKind::Domain(base) => scalar_for(base, money_digits),
        _ => <String as Type<Postgres>>::compatible(ty).then_some(Scalar::Text),
    }
}

/// The cell's bytes when it was sent in binary, which is how the driver asks
/// for every result. A text-format cell is not decoded as if it were.
fn wire_bytes<'r>(raw: &PgValueRef<'r>) -> Option<&'r [u8]> {
    match raw.format() {
        PgValueFormat::Binary => raw.as_bytes().ok(),
        PgValueFormat::Text => None,
    }
}

fn json_cell(text: &[u8], weight: &mut RowWeight<'_>) -> Result<Value, Refused> {
    match json::parse(text, weight) {
        JsonCell::Value(value) => Ok(value),
        JsonCell::OverBudget => Err(Refused::OverBudget),
        JsonCell::Invalid => Err(Refused::Undecodable),
    }
}

/// One decoder per column of `row`, in column order.
pub(super) fn decoders(row: &PgRow, money_digits: u8) -> Vec<ColumnDecoder> {
    row.columns()
        .iter()
        .map(|c| ColumnDecoder::for_type(sqlx::Column::type_info(c), money_digits))
        .collect()
}

/// Decode `row`, or stop as soon as its JSON cells outgrow `weight`.
pub(super) fn decode_row(
    row: &PgRow,
    decoders: &[ColumnDecoder],
    mut weight: RowWeight<'_>,
) -> Result<Vec<Value>, OverBudget> {
    decoders
        .iter()
        .enumerate()
        .map(|(idx, d)| d.decode(row, idx, &mut weight))
        .collect()
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::types::PgInterval;
    use sqlx::types::{BigDecimal, Json, Uuid};

    use super::*;

    #[test]
    fn builtin_types_pick_their_decoder() {
        fn ty<T: Type<Postgres>>() -> PgTypeInfo {
            T::type_info()
        }
        let scalar = ColumnDecoder::Scalar;
        let cases = [
            (ty::<i64>(), scalar(Scalar::Int8)),
            (ty::<f32>(), scalar(Scalar::Float4)),
            (ty::<Json<Value>>(), ColumnDecoder::Jsonb),
            (ty::<String>(), scalar(Scalar::Text)),
            (ty::<BigDecimal>(), scalar(Scalar::Numeric)),
            (ty::<PgInterval>(), scalar(Scalar::Interval)),
            (ty::<sqlx::postgres::types::Oid>(), scalar(Scalar::Oid)),
            (ty::<Vec<String>>(), ColumnDecoder::Array(Scalar::Text)),
            (ty::<Vec<i32>>(), ColumnDecoder::Array(Scalar::Int4)),
            (ty::<Vec<Uuid>>(), ColumnDecoder::Array(Scalar::Uuid)),
            (ty::<Vec<f64>>(), ColumnDecoder::Array(Scalar::Float8)),
            (ty::<Vec<bool>>(), ColumnDecoder::Array(Scalar::Bool)),
            (
                ty::<Vec<BigDecimal>>(),
                ColumnDecoder::Array(Scalar::Numeric),
            ),
            (
                ty::<sqlx::postgres::types::PgMoney>(),
                scalar(Scalar::Money(2)),
            ),
            (
                ty::<Vec<sqlx::postgres::types::PgMoney>>(),
                ColumnDecoder::Array(Scalar::Money(2)),
            ),
            (
                ty::<Vec<Json<Value>>>(),
                ColumnDecoder::Unsupported("JSONB[]".into()),
            ),
        ];
        for (ty, want) in cases {
            assert_eq!(ColumnDecoder::for_type(&ty, 2), want, "{ty:?}");
        }
    }
}
