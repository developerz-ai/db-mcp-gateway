//! Cells decoded from Postgres' binary wire form, one type at a time.
//!
//! Every type the gateway renders is read here from the bytes the server
//! sent, not through a driver type: a driver type holds less than Postgres
//! does (`numeric` scale, `NaN`, year 294276, `24:00:00`), and an array is
//! then the same element decoder applied in a loop.

use serde_json::Value;
use sqlx::postgres::types::PgInterval;
use uuid::Uuid;

use super::json::RowWeight;
use super::numeric::{money, numeric};
use super::{datetime, render};

/// Why a cell has no rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// The row cannot fit what the result budget has left.
    OverBudget,
    /// Not the bytes this type sends: the cell becomes the unsupported marker.
    Undecodable,
}

/// A type with a rendering, as a column or as an array's element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::exec::pg) enum Scalar {
    Bool,
    Int2,
    Int4,
    Int8,
    Float4,
    Float8,
    /// A JSON *string*: arbitrary precision is what money columns are made
    /// of, and `f64` would silently round it.
    Numeric,
    /// A JSON string like `numeric`, with this many digits after the point
    /// (see [`money`]). Not in [`Self::for_oid`]: the digits are the
    /// session's.
    Money(u8),
    /// Text-like types, `xml`, and enum labels.
    Text,
    Uuid,
    /// RFC 3339, normalised to UTC. Like every date/time type below:
    /// `infinity` / `-infinity` for Postgres' infinities, and a signed year
    /// outside `0000..=9999` (see [`datetime`]).
    TimestampTz,
    /// ISO-8601 with the `T` separator and no zone — Postgres stores none.
    Timestamp,
    Date,
    Time,
    TimeTz,
    /// `oid` and the types sent as one: `xid`, `cid` and the `reg*` aliases,
    /// whose binary form is the object's OID, not its name.
    Oid,
    Xid8,
    /// The one-byte `"char"` the catalogs use for flags.
    Char,
    TsVector,
    PgLsn,
    /// Postgres' own `\x`-prefixed hex, unmistakably not text.
    Bytea,
    /// ISO-8601 duration (`P1Y2M3DT4H5M6S`).
    Interval,
    /// `inet` / `cidr` in Postgres' text form.
    Inet,
}

impl Scalar {
    /// The decoder for a built-in type, whose OID never changes.
    pub(super) fn for_oid(oid: u32) -> Option<Self> {
        Some(match oid {
            16 => Self::Bool,
            21 => Self::Int2,
            23 => Self::Int4,
            20 => Self::Int8,
            700 => Self::Float4,
            701 => Self::Float8,
            1700 => Self::Numeric,
            // text, varchar, bpchar, name, xml, unknown
            25 | 1043 | 1042 | 19 | 142 | 705 => Self::Text,
            2950 => Self::Uuid,
            1184 => Self::TimestampTz,
            1114 => Self::Timestamp,
            1082 => Self::Date,
            1083 => Self::Time,
            1266 => Self::TimeTz,
            // oid, xid, cid, regproc, regprocedure, regoper, regoperator,
            // regclass, regtype, regconfig, regdictionary, regnamespace,
            // regrole, regcollation
            26 | 28 | 29 | 24 | 2202..=2206 | 3734 | 3769 | 4089 | 4096 | 4191 => Self::Oid,
            5069 => Self::Xid8,
            18 => Self::Char,
            3614 => Self::TsVector,
            3220 => Self::PgLsn,
            17 => Self::Bytea,
            1186 => Self::Interval,
            869 | 650 => Self::Inet,
            _ => return None,
        })
    }

    /// Text whose length follows the wire's is charged before it is built;
    /// a rendering of a fixed-width value, once built.
    pub(super) fn decode(self, wire: &[u8], weight: &mut RowWeight<'_>) -> Result<Value, Refused> {
        match self {
            Self::Numeric => return numeric(wire, weight).map(Value::from),
            Self::TsVector => return render::tsvector(wire, weight).map(Value::from),
            Self::Text => {
                charge(weight, wire.len())?;
                let text = String::from_utf8(wire.to_vec()).map_err(|_| Refused::Undecodable)?;
                return Ok(Value::from(text));
            }
            Self::Bytea => {
                charge(weight, render::hex_len(wire))?;
                return Ok(Value::from(render::hex(wire)));
            }
            _ => {}
        }
        let decoded = self.decode_fixed(wire).ok_or(Refused::Undecodable)?;
        if let Value::String(rendered) = &decoded {
            charge(weight, rendered.len())?;
        }
        Ok(decoded)
    }

    fn decode_fixed(self, wire: &[u8]) -> Option<Value> {
        let text = |rendered: Option<String>| rendered.map(Value::from);
        match self {
            Self::Bool => fixed(wire).map(|[byte]: [u8; 1]| Value::from(byte != 0)),
            Self::Int2 => fixed(wire).map(|b| Value::from(i16::from_be_bytes(b))),
            Self::Int4 => fixed(wire).map(|b| Value::from(i32::from_be_bytes(b))),
            Self::Int8 => fixed(wire).map(|b| Value::from(i64::from_be_bytes(b))),
            Self::Float4 => fixed(wire).map(|b| render::float(f64::from(f32::from_be_bytes(b)))),
            Self::Float8 => fixed(wire).map(|b| render::float(f64::from_be_bytes(b))),
            Self::Money(digits) => {
                fixed(wire).map(|b| Value::from(money(i64::from_be_bytes(b), digits)))
            }
            Self::Uuid => text(Uuid::from_slice(wire).ok().map(|uuid| uuid.to_string())),
            Self::TimestampTz => text(datetime::timestamptz(wire)),
            Self::Timestamp => text(datetime::timestamp(wire)),
            Self::Date => text(datetime::date(wire)),
            Self::Time => text(datetime::time(wire)),
            Self::TimeTz => text(datetime::timetz(wire)),
            Self::Oid => fixed(wire).map(|b| Value::from(u32::from_be_bytes(b))),
            Self::Xid8 => fixed(wire).map(|b| Value::from(u64::from_be_bytes(b))),
            Self::Char => {
                fixed(wire).map(|[byte]: [u8; 1]| Value::from(render::catalog_char(byte)))
            }
            Self::PgLsn => fixed(wire).map(|b| Value::from(render::lsn(u64::from_be_bytes(b)))),
            Self::Interval => interval(wire).map(|v| Value::from(render::interval(&v))),
            Self::Inet => text(render::inet(wire)),
            // Decoded above, against the budget.
            Self::Numeric | Self::TsVector | Self::Text | Self::Bytea => None,
        }
    }
}

fn charge(weight: &mut RowWeight<'_>, bytes: usize) -> Result<(), Refused> {
    if weight.charge(bytes) {
        Ok(())
    } else {
        Err(Refused::OverBudget)
    }
}

/// A fixed-width value: any other length is not this type.
fn fixed<const N: usize>(wire: &[u8]) -> Option<[u8; N]> {
    wire.try_into().ok()
}

/// Microseconds, days, months — kept apart, as Postgres keeps them.
fn interval(wire: &[u8]) -> Option<PgInterval> {
    let (micros, rest) = wire.split_first_chunk::<8>()?;
    let (days, months) = rest.split_first_chunk::<4>()?;
    Some(PgInterval {
        months: i32::from_be_bytes(fixed(months)?),
        days: i32::from_be_bytes(*days),
        microseconds: i64::from_be_bytes(*micros),
    })
}

/// A one-dimensional array of `element`: a JSON array whose items may be
/// `null`. The wire form is `dimensions, has-nulls flag, element OID`, a
/// `(length, lower bound)` pair per dimension, then each item behind its own
/// length (`-1` for NULL). Every item's [`Value`] is charged before any is
/// reserved — a `bool[]` item is five bytes on the wire and a whole `Value`
/// decoded — and each item's text as it is decoded.
pub(super) fn array(
    element: Scalar,
    wire: &[u8],
    weight: &mut RowWeight<'_>,
) -> Result<Value, Refused> {
    let mut reader = Reader(wire);
    let dimensions = reader.int()?;
    let (_has_nulls, _element_oid) = (reader.int()?, reader.int()?);
    let length = match dimensions {
        0 => 0,
        1 => {
            let (length, _lower_bound) = (reader.int()?, reader.int()?);
            usize::try_from(length).map_err(|_| Refused::Undecodable)?
        }
        // Nested arrays would need a shape; the marker says to cast.
        _ => return Err(Refused::Undecodable),
    };
    // An item is at least its four length bytes: more items than that is
    // a length the bytes do not back.
    if length > reader.0.len() / 4 {
        return Err(Refused::Undecodable);
    }
    charge(weight, length.saturating_mul(size_of::<Value>()))?;
    let mut items = Vec::with_capacity(length);
    for _ in 0..length {
        items.push(match usize::try_from(reader.int()?) {
            Ok(len) => element.decode(reader.take(len)?, weight)?,
            Err(_) => Value::Null,
        });
    }
    if reader.0.is_empty() {
        Ok(Value::Array(items))
    } else {
        Err(Refused::Undecodable)
    }
}

/// The unread rest of an array's wire form.
struct Reader<'w>(&'w [u8]);

impl<'w> Reader<'w> {
    fn int(&mut self) -> Result<i32, Refused> {
        let (int, rest) = self
            .0
            .split_first_chunk::<4>()
            .ok_or(Refused::Undecodable)?;
        self.0 = rest;
        Ok(i32::from_be_bytes(*int))
    }

    fn take(&mut self, len: usize) -> Result<&'w [u8], Refused> {
        let (taken, rest) = self.0.split_at_checked(len).ok_or(Refused::Undecodable)?;
        self.0 = rest;
        Ok(taken)
    }
}

#[cfg(test)]
mod tests;
