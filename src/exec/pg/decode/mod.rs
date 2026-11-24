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
mod render;

use serde_json::Value;
use sqlx::postgres::{PgRow, PgTypeInfo, PgTypeKind, PgValueFormat, PgValueRef, Postgres};
use sqlx::types::{BigDecimal, Json, Uuid, chrono};
use sqlx::{Row, Type, TypeInfo, ValueRef};

use json::JsonCell;
pub(super) use json::RowWeight;
use render::{float, hex, inet, interval, unsupported};

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
    Int8,
    Int4,
    Int2,
    Float8,
    Float4,
    Bool,
    /// Text-like columns and enum labels.
    Text,
    /// `numeric` as a JSON *string*: arbitrary precision is what money
    /// columns are made of, and `f64` would silently round it.
    Numeric,
    Uuid,
    /// RFC 3339, normalised to UTC. Like every date/time decoder below:
    /// `infinity` / `-infinity` for Postgres' infinities, and a signed year
    /// outside `0000..=9999` (see [`datetime`]).
    TimestampTz,
    /// ISO-8601 with the `T` separator and no zone — Postgres stores none.
    Timestamp,
    Date,
    Time,
    /// Postgres' own `\x`-prefixed hex, unmistakably not text.
    Bytea,
    /// ISO-8601 duration (`P1Y2M3DT4H5M6S`).
    Interval,
    /// `inet` / `cidr` in Postgres' text form.
    Inet,
    TextArray,
    Int8Array,
    Int4Array,
    Int2Array,
    UuidArray,
    /// Arrays of other types, ranges, PostGIS, composites …: the marker names
    /// the type so the caller can cast it (`SELECT my_col::text`).
    Unsupported(String),
}

impl ColumnDecoder {
    pub(super) fn for_type(ty: &PgTypeInfo) -> Self {
        // Compatibility, not name, decides: `Json` covers `json` and `jsonb`,
        // `String` covers every text-like type sqlx knows. sqlx enforces
        // width per OID, so each integer and float width is its own variant.
        if is::<Json<Value>>(ty) {
            if ty.name() == "JSONB" {
                Self::Jsonb
            } else {
                Self::Json
            }
        } else if is::<i64>(ty) {
            Self::Int8
        } else if is::<i32>(ty) {
            Self::Int4
        } else if is::<i16>(ty) {
            Self::Int2
        } else if is::<f64>(ty) {
            Self::Float8
        } else if is::<f32>(ty) {
            Self::Float4
        } else if is::<bool>(ty) {
            Self::Bool
        } else if is::<String>(ty) {
            Self::Text
        } else if is::<BigDecimal>(ty) {
            Self::Numeric
        } else if is::<Uuid>(ty) {
            Self::Uuid
        } else if is::<chrono::DateTime<chrono::Utc>>(ty) {
            Self::TimestampTz
        } else if is::<chrono::NaiveDateTime>(ty) {
            Self::Timestamp
        } else if is::<chrono::NaiveDate>(ty) {
            Self::Date
        } else if is::<chrono::NaiveTime>(ty) {
            Self::Time
        } else if is::<Vec<u8>>(ty) {
            Self::Bytea
        } else if is::<sqlx::postgres::types::PgInterval>(ty) {
            Self::Interval
        } else if matches!(ty.name(), "INET" | "CIDR") {
            Self::Inet
        } else if is::<Vec<Option<String>>>(ty) {
            Self::TextArray
        } else if is::<Vec<Option<i64>>>(ty) {
            Self::Int8Array
        } else if is::<Vec<Option<i32>>>(ty) {
            Self::Int4Array
        } else if is::<Vec<Option<i16>>>(ty) {
            Self::Int2Array
        } else if is::<Vec<Option<Uuid>>>(ty) {
            Self::UuidArray
        } else {
            match ty.kind() {
                // An enum's binary form is its label's UTF-8 bytes.
                PgTypeKind::Enum(_) => Self::Text,
                // A domain is sent in its base type's format.
                PgTypeKind::Domain(base) => Self::for_type(base),
                _ => Self::Unsupported(ty.name().to_string()),
            }
        }
    }

    fn decode(
        &self,
        row: &PgRow,
        idx: usize,
        weight: &mut RowWeight<'_>,
    ) -> Result<Value, OverBudget> {
        // Type-agnostic NULL check first: decoding is unchecked below (the
        // decoder already matched the column type, and a domain's OID would
        // fail the checked path), so NULL must never reach it.
        let Ok(raw) = row.try_get_raw(idx) else {
            // Unreachable: `idx` comes from this row's own column list.
            return Ok(unsupported("unknown"));
        };
        if raw.is_null() {
            return Ok(Value::Null);
        }
        let decoded = match self {
            Self::Json | Self::Jsonb => match json_text(self, &raw).map(|t| json::parse(t, weight))
            {
                Some(JsonCell::Value(value)) => Ok(value),
                Some(JsonCell::OverBudget) => return Err(OverBudget),
                Some(JsonCell::Invalid) | None => Err(()),
            },
            Self::Int8 => get::<i64>(row, idx).map(Value::from),
            Self::Int4 => get::<i32>(row, idx).map(Value::from),
            Self::Int2 => get::<i16>(row, idx).map(Value::from),
            Self::Float8 => get::<f64>(row, idx).map(float),
            Self::Float4 => get::<f32>(row, idx).map(|v| float(f64::from(v))),
            Self::Bool => get::<bool>(row, idx).map(Value::from),
            Self::Text => get::<String>(row, idx).map(Value::from),
            Self::Numeric => get::<BigDecimal>(row, idx).map(|v| Value::from(v.to_string())),
            Self::Uuid => get::<Uuid>(row, idx).map(|v| Value::from(v.to_string())),
            Self::TimestampTz => datetime::timestamptz(&raw).map(Value::from).ok_or(()),
            Self::Timestamp => datetime::timestamp(&raw).map(Value::from).ok_or(()),
            Self::Date => datetime::date(&raw).map(Value::from).ok_or(()),
            Self::Time => datetime::time(&raw).map(Value::from).ok_or(()),
            Self::Bytea => get::<Vec<u8>>(row, idx).map(|v| Value::from(hex(&v))),
            Self::Interval => get::<sqlx::postgres::types::PgInterval>(row, idx)
                .map(|v| Value::from(interval(&v))),
            Self::Inet => inet(&raw).map(Value::from).ok_or(()),
            Self::TextArray => get::<Vec<Option<String>>>(row, idx).map(Value::from),
            Self::Int8Array => get::<Vec<Option<i64>>>(row, idx).map(Value::from),
            Self::Int4Array => get::<Vec<Option<i32>>>(row, idx).map(Value::from),
            Self::Int2Array => get::<Vec<Option<i16>>>(row, idx).map(Value::from),
            Self::UuidArray => get::<Vec<Option<Uuid>>>(row, idx)
                .map(|v| Value::from_iter(v.into_iter().map(|u| u.map(|u| u.to_string())))),
            Self::Unsupported(name) => return Ok(unsupported(name)),
        };
        Ok(decoded.unwrap_or_else(|()| unsupported(raw.type_info().name())))
    }
}

/// The JSON text of a `json` / `jsonb` cell: binary `jsonb` leads with its
/// format version, and version 1 is the only one there is.
fn json_text<'r>(decoder: &ColumnDecoder, raw: &PgValueRef<'r>) -> Option<&'r [u8]> {
    let bytes = raw.as_bytes().ok()?;
    if *decoder == ColumnDecoder::Jsonb && raw.format() == PgValueFormat::Binary {
        return bytes.strip_prefix(&[1]);
    }
    Some(bytes)
}

/// One decoder per column of `row`, in column order.
pub(super) fn decoders(row: &PgRow) -> Vec<ColumnDecoder> {
    row.columns()
        .iter()
        .map(|c| ColumnDecoder::for_type(sqlx::Column::type_info(c)))
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

fn is<T: Type<Postgres>>(ty: &PgTypeInfo) -> bool {
    T::compatible(ty)
}

/// Unchecked decode: the column's decoder was chosen by compatibility, so
/// sqlx's per-cell type check would only repeat it (and reject domains). A
/// failure is still caught and rendered as the unsupported marker.
fn get<'r, T>(row: &'r PgRow, idx: usize) -> Result<T, ()>
where
    T: sqlx::Decode<'r, Postgres>,
{
    row.try_get_unchecked::<T, _>(idx).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_types_pick_their_decoder() {
        fn ty<T: Type<Postgres>>() -> PgTypeInfo {
            T::type_info()
        }
        let cases = [
            (ty::<i64>(), ColumnDecoder::Int8),
            (ty::<f32>(), ColumnDecoder::Float4),
            (ty::<Json<Value>>(), ColumnDecoder::Jsonb),
            (ty::<String>(), ColumnDecoder::Text),
            (ty::<BigDecimal>(), ColumnDecoder::Numeric),
            (
                ty::<sqlx::postgres::types::PgInterval>(),
                ColumnDecoder::Interval,
            ),
            (ty::<Vec<String>>(), ColumnDecoder::TextArray),
            (ty::<Vec<i32>>(), ColumnDecoder::Int4Array),
            (ty::<Vec<Uuid>>(), ColumnDecoder::UuidArray),
            (
                ty::<Vec<f64>>(),
                ColumnDecoder::Unsupported("FLOAT8[]".into()),
            ),
        ];
        for (ty, want) in cases {
            assert_eq!(ColumnDecoder::for_type(&ty), want, "{ty:?}");
        }
    }
}
