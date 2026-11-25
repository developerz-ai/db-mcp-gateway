//! Recasting helpers for Postgres reads whose result columns the driver
//! cannot take in binary form.
//!
//! The gateway never invents a value for a column it cannot decode. A caller
//! that describes such a read gets the wrapper's SQL back in `recast`, and
//! the next `run_query` sends that wrapper with its own params; the cells
//! come back as text the client can parse. The wrapper casts only the columns
//! the driver cannot take, and casts nested array elements when the array's
//! element type cannot be taken.
//!
//! Whether a read needs the wrapper is decided before it runs (see
//! `describe`), never by retrying a failure: the read runs once (#382).
//! Before the caller's statement is nested it is prepared alone over the
//! extended protocol, which refuses more than one statement: the text is
//! proven a single statement first, as the unnamed statement, so an abort
//! leaves nothing for a transaction-mode pooler to hand to another caller.
//! When the driver cannot describe the statement at all (a category-`Z`
//! column), its columns are read from a cursor over a wrapper that reads no
//! row of it: the cursor is declared over the extended protocol with the
//! caller's own params, and its row has one column for each the description
//! does not look up. Nothing runs with a made-up param value (#383).

use sqlx::postgres::types::Oid;
use sqlx::{Column, Executor, Postgres, SqlSafeStr, Statement as _, Transaction};

use super::super::query::{ExecQuery, QueryParam};
use super::super::sql_guard::statement_body;
use super::stream::{bound_query, bound_types};

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
    prove_single_statement(tx, body, query.binds, params).await?;
    let columns: Vec<(&str, bool)> = columns
        .iter()
        .map(|(name, oid)| (name.as_str(), textless.contains(oid)))
        .collect();
    Ok(Some(wrap(body, &columns)))
}

/// The columns of `query`'s statement when the driver could not describe it.
/// `LIMIT 0` forces the planner to resolve every output column without the
/// server running the statement, so no row is read twice (#382). Cancelling
/// that describe cancels the backend; nothing runs with a made-up param.
pub(super) async fn row_description(
    tx: &mut Transaction<'_, Postgres>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
) -> Result<Vec<(String, u32)>, sqlx::Error> {
    let Some(body) = statement_body(query.sql) else {
        return Ok(Vec::new());
    };
    prove_single_statement(tx, body, query.binds, params).await?;
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

/// `body` parsed alone, with the binds and params it will run with: a second
/// statement in it is refused here, before it is nested. This is the
/// protocol's unnamed statement (see `config`), so cancellation or an abort
/// leaves no named statement for a pooled backend to hand to another call.
/// The body is nested under `SELECT 1 FROM (…) LIMIT 0` so only the constant
/// wrapper column is described. Parsing still resolves every placeholder and
/// refuses a second statement, and `LIMIT 0` keeps the body from supplying a
/// row, which would fail on a category-`Z` column the driver cannot decode.
async fn prove_single_statement(
    tx: &mut Transaction<'_, Postgres>,
    body: &str,
    binds: &[&str],
    params: &[QueryParam],
) -> Result<(), sqlx::Error> {
    let proof = format!("SELECT 1 FROM (\n{body}\n) AS q LIMIT 0");
    let types = bound_types(binds, params);
    let statement = (&mut **tx)
        .prepare_with(sqlx::AssertSqlSafe(proof).into_sql_str(), &types)
        .await?;
    let _ = statement.columns();
    Ok(())
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
    format!("\"{}\"", name.replace('\"', "\"\""))
}

#[cfg(test)]
#[path = "recast_tests.rs"]
mod recast_tests;
