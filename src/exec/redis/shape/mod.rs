//! Reply → rows. Each accepted command answers in one fixed [`Shape`],
//! decided from the command and its flags before it is sent, so the columns
//! an agent sees never depend on what happens to be stored.

use redis::Value as Reply;
use serde_json::{Map, Value};

use super::super::adapter::ExecError;
use super::super::budget::ResultBudget;
use super::value_json::{key_text, to_json};

/// The tabular form of one command's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `["value"]`: a scalar is one row, an array one row per element.
    Value,
    /// `["field","value"]`: `HGETALL`, `HRANDFIELD … WITHVALUES`.
    FieldValue,
    /// `["member","score"]`: sorted-set reads `… WITHSCORES`.
    MemberScore,
    /// `["next_cursor", …item]`: one row per item of a `*SCAN` page.
    Scan(ScanItem),
    /// `["id","fields"]`: `XRANGE` / `XREVRANGE`, fields as a JSON object.
    Stream,
}

/// What one `*SCAN` page item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanItem {
    Key,
    Member,
    FieldValue,
    MemberScore,
}

impl Shape {
    /// The shape `command` (canonical upper case) answers in, given its
    /// arguments (`args[0]` is the first argument after the name).
    pub(super) fn for_command(command: &str, args: &[String]) -> Self {
        match command {
            "HGETALL" => Self::FieldValue,
            "HRANDFIELD" if has_flag(args, 2, "WITHVALUES") => Self::FieldValue,
            "ZRANGE" | "ZRANGEBYSCORE" | "ZREVRANGE" | "ZREVRANGEBYSCORE"
                if has_flag(args, 3, "WITHSCORES") =>
            {
                Self::MemberScore
            }
            "ZRANDMEMBER" if has_flag(args, 2, "WITHSCORES") => Self::MemberScore,
            "SCAN" => Self::Scan(ScanItem::Key),
            "SSCAN" => Self::Scan(ScanItem::Member),
            "HSCAN" => Self::Scan(ScanItem::FieldValue),
            "ZSCAN" => Self::Scan(ScanItem::MemberScore),
            "XRANGE" | "XREVRANGE" => Self::Stream,
            _ => Self::Value,
        }
    }
}

/// `flag` anywhere from position `from` on — past the key and any range
/// bounds, so a bound can never be mistaken for the flag.
fn has_flag(args: &[String], from: usize, flag: &str) -> bool {
    args.iter()
        .skip(from)
        .any(|arg| arg.eq_ignore_ascii_case(flag))
}

/// The rows of one reply, cut at the row and byte budget.
#[derive(Debug)]
pub(super) struct Shaped {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
}

/// Lay `reply` out as `shape`. A reply that does not fit the shape the
/// command documents is a [`ExecError::Decode`], never padded with `null`.
pub(super) fn shape_reply(shape: Shape, reply: Reply, row_limit: u32) -> Result<Shaped, ExecError> {
    match (shape, reply) {
        // RESP3 servers answer field/value replies as maps whatever the shape.
        (Shape::Value | Shape::FieldValue, Reply::Map(pairs)) => collect(
            &["field", "value"],
            pairs.into_iter().map(pair_row),
            row_limit,
        ),
        (Shape::Value, Reply::Array(items) | Reply::Set(items)) => collect(
            &["value"],
            items.into_iter().map(|item| to_json(item).map(|v| vec![v])),
            row_limit,
        ),
        (Shape::Value, scalar) => {
            let row = to_json(scalar).map(|v| vec![v]);
            collect(&["value"], std::iter::once(row), row_limit)
        }
        (Shape::FieldValue, reply) => paired(&["field", "value"], reply, row_limit),
        (Shape::MemberScore, reply) => paired(&["member", "score"], reply, row_limit),
        (Shape::Scan(item), reply) => scan_page(item, reply, row_limit),
        (Shape::Stream, reply) => stream_entries(reply, row_limit),
    }
}

/// Field/value or member/score pairs: a RESP2 flat array, a RESP3 array of
/// two-element arrays, or a map. A missing key answers an empty array (or
/// nil), which is zero rows.
fn paired(columns: &[&str], reply: Reply, row_limit: u32) -> Result<Shaped, ExecError> {
    let pairs = into_pairs(reply)?;
    collect(columns, pairs.into_iter().map(pair_row), row_limit)
}

fn into_pairs(reply: Reply) -> Result<Vec<(Reply, Reply)>, ExecError> {
    match reply {
        Reply::Nil => Ok(Vec::new()),
        Reply::Map(pairs) => Ok(pairs),
        Reply::Array(items)
            if items
                .iter()
                .all(|i| matches!(i, Reply::Array(p) if p.len() == 2)) =>
        {
            items
                .into_iter()
                .map(|item| match item {
                    Reply::Array(pair) => two(pair),
                    _ => Err(ExecError::Decode),
                })
                .collect()
        }
        Reply::Array(items) => {
            if items.len() % 2 != 0 {
                return Err(ExecError::Decode);
            }
            let mut flat = items.into_iter();
            let mut pairs = Vec::with_capacity(flat.len() / 2);
            while let (Some(first), Some(second)) = (flat.next(), flat.next()) {
                pairs.push((first, second));
            }
            Ok(pairs)
        }
        _ => Err(ExecError::Decode),
    }
}

fn two(pair: Vec<Reply>) -> Result<(Reply, Reply), ExecError> {
    let mut items = pair.into_iter();
    match (items.next(), items.next(), items.next()) {
        (Some(first), Some(second), None) => Ok((first, second)),
        _ => Err(ExecError::Decode),
    }
}

/// One converted row, or why the reply could not be converted.
type Row = Result<Vec<Value>, ExecError>;

fn pair_row((first, second): (Reply, Reply)) -> Row {
    Ok(vec![to_json(first)?, to_json(second)?])
}

/// A `*SCAN` page is bounded by the clamped `COUNT`, so its rows are
/// converted up front.
fn single_rows(items: Vec<Reply>) -> Vec<Row> {
    items
        .into_iter()
        .map(|i| to_json(i).map(|v| vec![v]))
        .collect()
}

fn pair_rows(items: Reply) -> Result<Vec<Row>, ExecError> {
    Ok(into_pairs(items)?.into_iter().map(pair_row).collect())
}

/// `[cursor, [items…]]`: one row per item, each led by the next cursor. An
/// empty page is one row with null items, so the cursor is never lost.
fn scan_page(item: ScanItem, reply: Reply, row_limit: u32) -> Result<Shaped, ExecError> {
    let Reply::Array(page) = reply else {
        return Err(ExecError::Decode);
    };
    let (cursor, items) = two(page)?;
    let cursor = to_json(cursor)?;
    let Reply::Array(items) = items else {
        return Err(ExecError::Decode);
    };
    let (columns, rows): (&[&str], Vec<Row>) = match item {
        ScanItem::Key => (&["next_cursor", "key"], single_rows(items)),
        ScanItem::Member => (&["next_cursor", "member"], single_rows(items)),
        ScanItem::FieldValue => (
            &["next_cursor", "field", "value"],
            pair_rows(Reply::Array(items))?,
        ),
        ScanItem::MemberScore => (
            &["next_cursor", "member", "score"],
            pair_rows(Reply::Array(items))?,
        ),
    };
    let rows = if rows.is_empty() {
        vec![Ok(vec![Value::Null; columns.len() - 1])]
    } else {
        rows
    };
    let led = rows.into_iter().map(|row| {
        row.map(|mut cells| {
            cells.insert(0, cursor.clone());
            cells
        })
    });
    collect(columns, led, row_limit)
}

/// `[[id, [field, value, …]], …]` → `[id, {field: value}]` per entry.
fn stream_entries(reply: Reply, row_limit: u32) -> Result<Shaped, ExecError> {
    let entries = match reply {
        Reply::Nil => Vec::new(),
        Reply::Array(entries) => entries,
        _ => return Err(ExecError::Decode),
    };
    let rows = entries.into_iter().map(|entry| {
        let Reply::Array(entry) = entry else {
            return Err(ExecError::Decode);
        };
        let (id, fields) = two(entry)?;
        let mut object = Map::new();
        for (field, value) in into_pairs(fields)? {
            object.insert(key_text(field)?, to_json(value)?);
        }
        Ok(vec![to_json(id)?, Value::Object(object)])
    });
    collect(&["id", "fields"], rows, row_limit)
}

/// Admit rows until the budget runs out. Lazy rows are converted only once
/// the budget has room for them; `truncated` is set only when a row was left
/// behind.
fn collect(
    columns: &[&str],
    rows: impl Iterator<Item = Row>,
    row_limit: u32,
) -> Result<Shaped, ExecError> {
    let mut budget = ResultBudget::new(row_limit);
    let mut admitted = Vec::new();
    let mut truncated = false;
    for row in rows {
        if !budget.has_row_left() {
            truncated = true;
            break;
        }
        let row = row?;
        if !budget.admit(&row) {
            truncated = true;
            break;
        }
        admitted.push(row);
    }
    Ok(Shaped {
        columns: columns.iter().map(|c| (*c).to_string()).collect(),
        rows: admitted,
        truncated,
    })
}

#[cfg(test)]
mod tests;
