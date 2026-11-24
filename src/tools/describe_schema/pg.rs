//! Postgres `describe_schema` payloads, one per [`Detail`], from the
//! adapter's rows (see `DbAdapter::describe_schema`). `schemas` is listed
//! when the call named no schema.

use serde::Serialize;
use serde_json::Value;

use crate::exec::ExecResult;

use super::Detail;

#[derive(Debug, Serialize)]
struct ColumnView {
    name: String,
    data_type: String,
    nullable: bool,
}

#[derive(Debug, Serialize)]
struct TableView {
    schema: String,
    name: String,
    columns: Vec<ColumnView>,
}

#[derive(Debug, Serialize)]
struct NameView<'a> {
    schema: &'a str,
    name: &'a str,
    kind: &'a str,
}

/// One relation at `detail: full`; the JSON parts are the server's,
/// passed through.
#[derive(Debug, Serialize)]
struct FullView<'a> {
    schema: &'a str,
    name: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'a str>,
    row_estimate: Option<i64>,
    columns: &'a Value,
    primary_key: &'a Value,
    foreign_keys: &'a Value,
    indexes: &'a Value,
}

#[derive(Debug, Serialize)]
struct Payload<T> {
    tables: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schemas: Option<Vec<String>>,
    /// The catalog scan hit its cap: tables past the cut are missing (at
    /// `columns`, the table the cut fell in was dropped rather than returned
    /// with only some of its columns).
    truncated: bool,
}

/// `(tables listed, payload JSON)`, or `Err` when a row is not the shape the
/// adapter documents.
pub(super) fn render(
    detail: Detail,
    result: &ExecResult,
    schemas: Option<Vec<String>>,
) -> Result<(usize, String), ()> {
    let truncated = result.truncated;
    match detail {
        Detail::Columns => to_json(assemble_tables(result)?, schemas, truncated),
        Detail::Names => {
            let tables: Result<Vec<_>, ()> = result.rows.iter().map(|r| name_view(r)).collect();
            to_json(tables?, schemas, truncated)
        }
        Detail::Full => {
            let tables: Result<Vec<_>, ()> = result.rows.iter().map(|r| full_view(r)).collect();
            to_json(tables?, schemas, truncated)
        }
    }
}

fn to_json<T: Serialize>(
    tables: Vec<T>,
    schemas: Option<Vec<String>>,
    truncated: bool,
) -> Result<(usize, String), ()> {
    let count = tables.len();
    let payload = Payload {
        tables,
        schemas,
        truncated,
    };
    serde_json::to_string(&payload)
        .map(|text| (count, text))
        .map_err(|_| ())
}

fn text(value: &Value) -> Result<&str, ()> {
    value.as_str().ok_or(())
}

fn name_view(row: &[Value]) -> Result<NameView<'_>, ()> {
    match row {
        [schema, name, kind] => Ok(NameView {
            schema: text(schema)?,
            name: text(name)?,
            kind: text(kind)?,
        }),
        _ => Err(()),
    }
}

fn full_view(row: &[Value]) -> Result<FullView<'_>, ()> {
    let [
        schema,
        name,
        kind,
        comment,
        row_estimate,
        columns,
        primary_key,
        foreign_keys,
        indexes,
    ] = row
    else {
        return Err(());
    };
    Ok(FullView {
        schema: text(schema)?,
        name: text(name)?,
        kind: text(kind)?,
        comment: comment.as_str(),
        row_estimate: row_estimate.as_i64(),
        columns,
        primary_key,
        foreign_keys,
        indexes,
    })
}

/// Group `information_schema.columns` rows by `(schema, table_name)` into the
/// nested `tables` shape clients want. When the scan was capped, the last
/// table may be missing columns, so it is dropped: every table returned is
/// complete.
fn assemble_tables(result: &ExecResult) -> Result<Vec<TableView>, ()> {
    let mut tables: Vec<TableView> = Vec::new();
    for row in &result.rows {
        let [schema, table, column, data_type, is_nullable] = row.as_slice() else {
            return Err(());
        };
        let (schema, table) = (text(schema)?, text(table)?);
        let column = ColumnView {
            name: text(column)?.to_string(),
            data_type: text(data_type)?.to_string(),
            // `is_nullable` from information_schema is the text "YES"/"NO".
            nullable: is_nullable.as_str() == Some("YES"),
        };
        match tables.last_mut() {
            Some(t) if t.schema == schema && t.name == table => t.columns.push(column),
            _ => tables.push(TableView {
                schema: schema.to_string(),
                name: table.to_string(),
                columns: vec![column],
            }),
        }
    }
    if result.truncated {
        tables.pop();
    }
    Ok(tables)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
