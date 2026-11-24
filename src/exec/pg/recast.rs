//! The text cast for a read whose result has a column the driver cannot
//! take.
//!
//! The driver asks for every result in binary and looks every unfamiliar
//! column type up in the catalog first. Two kinds of type defeat that, and
//! with it the whole statement: a type with no binary output function (an
//! extension type that never wrote one, or `aclitem` inside `relacl`'s
//! array), which the server refuses at `Bind` (`42883`) — or, as an array's
//! element, only while it sends the first row, after the statement's
//! functions ran; and an internal type (category `Z`: `pg_node_tree`, as in
//! `pg_class.relpartbound`, or `pg_ndistinct` …), whose catalog row the
//! driver cannot read. Those columns, and only those, are cast to `text` by
//! wrapping the caller's statement:
//!
//! ```sql
//! SELECT q.c1 AS "oid", q.c2::text AS "relacl" FROM (
//! <caller's statement>
//! ) AS q(c1, c2)
//! ```
//!
//! The wrapper reads its columns by position, so duplicate or odd output
//! names survive, and it keeps them as the column names. It runs in the
//! read's own read-only transaction instead of the caller's statement, which
//! is not changed, only nested.
//!
//! Whether a read needs the wrapper is decided before it runs (see
//! `describe`), never by retrying a failure: the read runs once (#382).
//! Before the caller's statement is nested it is `PREPARE`d alone over the
//! extended protocol, which refuses more than one statement: the text is
//! proven a single statement first. When the driver cannot describe the
//! statement at all (a category-`Z` column), its columns are read from a
//! cursor over a wrapper that reads no row of it: the cursor is declared
//! over the extended protocol with the caller's own params, and its row
//! description fetched over the simple protocol, whose types the driver
//! does not look up. Nothing runs with a made-up param value (#383).

use sqlx::postgres::types::Oid;
use sqlx::{Column, Executor, Postgres, Transaction};

use super::super::query::{ExecQuery, QueryParam};
use super::super::sql_guard::statement_body;
use super::stream::bound_query;

/// `query`'s statement with every one of `columns` (name and type OID, in
/// order) the driver cannot take cast to text, or `None` when there is no
/// such column.
pub(super) async fn text_cast_sql(
    tx: &mut Transaction<'_, Postgres>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
    columns: &[(String, u32)],
) -> Result<Option<String>, sqlx::Error> {
    let Some(body) = statement_body(query.sql) else {
        return Ok(None);
    };
    let oids: Vec<u32> = columns.iter().map(|(_, oid)| *oid).collect();
    if oids.is_empty() {
        return Ok(None);
    }
    let textless = untakeable(tx, &oids).await?;
    if textless.is_empty() {
        return Ok(None);
    }
    prove_single_statement(tx, body, params).await?;
    let columns: Vec<(&str, bool)> = columns
        .iter()
        .map(|(name, oid)| (name.as_str(), textless.contains(oid)))
        .collect();
    Ok(Some(wrap(body, &columns)))
}

/// `query`'s result columns, name and type OID, read without the driver's
/// type lookup and without running the statement.
pub(super) async fn row_description(
    tx: &mut Transaction<'_, Postgres>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
) -> Result<Vec<(String, u32)>, sqlx::Error> {
    let Some(body) = statement_body(query.sql) else {
        return Ok(Vec::new());
    };
    prove_single_statement(tx, body, params).await?;
    // `LIMIT 0` never asks its input for a row: the caller's statement is
    // planned with its params, and none of it runs.
    let declare = format!(
        "DECLARE dbmcp_columns NO SCROLL CURSOR FOR SELECT q.* FROM (SELECT 1) AS one \
         LEFT JOIN (SELECT * FROM (\n{body}\n) AS s LIMIT 0) AS q ON true"
    );
    bound_query(sqlx::AssertSqlSafe(declare), query.binds, params)
        .execute(&mut **tx)
        .await?;
    let row = (&mut **tx)
        .fetch_optional("FETCH 1 FROM dbmcp_columns")
        .await?;
    tx.execute("CLOSE dbmcp_columns").await?;
    let columns = row.map(|row| {
        sqlx::Row::columns(&row)
            .iter()
            .map(|c| {
                (
                    c.name().to_string(),
                    c.type_info().oid().map_or(0, |oid| oid.0),
                )
            })
            .collect()
    });
    Ok(columns.unwrap_or_default())
}

/// `body` prepared alone, with the types `params` run with: a second
/// statement in it is refused here, before it is nested.
async fn prove_single_statement(
    tx: &mut Transaction<'_, Postgres>,
    body: &str,
    params: &[QueryParam],
) -> Result<(), sqlx::Error> {
    let prepare = format!("PREPARE dbmcp_recast{} AS\n{body}", param_types(params));
    sqlx::query(sqlx::AssertSqlSafe(prepare))
        .persistent(false)
        .execute(&mut **tx)
        .await?;
    tx.execute("DEALLOCATE dbmcp_recast").await?;
    Ok(())
}

/// The `PREPARE` type list for the types `params` run with (see
/// [`QueryParam`]), empty without params. Every name is a constant.
fn param_types(params: &[QueryParam]) -> String {
    if params.is_empty() {
        return String::new();
    }
    let types: Vec<&str> = params
        .iter()
        .map(|param| match param {
            QueryParam::Null => "unknown",
            QueryParam::Bool(_) => "bool",
            QueryParam::Int(_) => "int8",
            QueryParam::Float(_) => "float8",
            QueryParam::Text(_) => "text",
            QueryParam::Json(_) => "jsonb",
        })
        .collect();
    format!(" ({})", types.join(", "))
}

/// Which of `types` the driver cannot take, themselves or as an array's
/// element. The OIDs are numbers, so they are interpolated, not bound.
async fn untakeable(
    tx: &mut Transaction<'_, Postgres>,
    types: &[u32],
) -> Result<Vec<u32>, sqlx::Error> {
    let listed = types
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT t.oid FROM pg_type t LEFT JOIN pg_type e ON e.oid = t.typelem \
         WHERE t.oid IN ({listed}) AND (t.typsend::oid = 0 OR t.typcategory = 'Z' \
         OR (t.typcategory = 'A' AND (e.typsend::oid = 0 OR e.typcategory = 'Z')))"
    );
    let found: Vec<Oid> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .persistent(false)
        .fetch_all(&mut **tx)
        .await?;
    Ok(found.into_iter().map(|oid| oid.0).collect())
}

/// The wrapper statement: `columns` are each output column's name and
/// whether it is cast to text.
fn wrap(body: &str, columns: &[(&str, bool)]) -> String {
    let select = columns
        .iter()
        .enumerate()
        .map(|(at, (name, cast))| {
            let cast = if *cast { "::text" } else { "" };
            format!("q.c{}{cast} AS {}", at + 1, quote_ident(name))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let aliases = (1..=columns.len())
        .map(|at| format!("c{at}"))
        .collect::<Vec<_>>()
        .join(", ");
    // The newline ends a trailing `--` comment before the parenthesis.
    format!("SELECT {select} FROM (\n{body}\n) AS q({aliases})")
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
#[path = "recast_tests.rs"]
mod tests;
