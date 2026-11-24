//! What a read returns, asked before it runs (#382). The statement is
//! prepared — Parse/Describe over the extended protocol, which never
//! executes it — with the types its params will be bound with, so `SELECT
//! $1 AS v` is described as the read will run. The driver keeps the
//! prepared statement and the read binds and executes it. The driver
//! prepares every statement before binding it anyway, so a warm read takes
//! no more round trips than without this; it adds a `Close` at release and
//! one catalog lookup per connection and newly seen table.
//!
//! The description decides whether a column the driver cannot take needs
//! the text cast (see [`recast`]), so the statement that runs is the one
//! that answers: a read never runs twice, and its side effects (a volatile
//! function) never repeat. It also names a zero-row read's columns (#136).

use sqlx::postgres::{PgStatement, PgTypeInfo};
use sqlx::{Column, Executor, Postgres, SqlSafeStr, Statement, Transaction, TypeInfo};

use super::super::adapter::ExecError;
use super::super::query::{ExecQuery, QueryParam};
use super::decode::ColumnDecoder;
use super::error::{Origin, classify};
use super::recast;
use super::stream::bound_types;

/// The statement a read runs and what it returns.
pub(super) struct Described {
    /// The text-cast wrapper to run instead of the caller's statement.
    pub(super) recast: Option<String>,
    pub(super) columns: Vec<String>,
    /// The server's type name per column (`int4`, `text`, …).
    pub(super) column_types: Vec<String>,
}

/// Describe `query`, a read, and decide the statement to run. A statement
/// that does not prepare is the read's answer, as if it had run.
pub(super) async fn describe_read(
    tx: &mut Transaction<'_, Postgres>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
    origin: &Origin<'_>,
) -> Result<Described, ExecError> {
    let types = bound_types(query.binds, params);
    let statement = match prepare(tx, query.sql, &types).await {
        Ok(statement) => statement,
        // A type the driver cannot look up fails here, after Parse and
        // before anything ran; the server's own refusals stand.
        Err(err) => {
            let refused = classify(err, origin, query.sql);
            if !matches!(refused, ExecError::Sql) {
                return Err(refused);
            }
            let wrapper = match recast::row_description(tx, query, params).await {
                Ok(columns) => recast::text_cast_sql(tx, query, params, &columns).await,
                Err(err) => Err(err),
            };
            return match wrapper {
                Ok(Some(wrapper)) => described_recast(tx, wrapper, &types, origin).await,
                _ => Err(refused),
            };
        }
    };
    let columns: Vec<(String, u32)> = statement
        .columns()
        .iter()
        .map(|c| {
            (
                c.name().to_string(),
                c.type_info().oid().map_or(0, |oid| oid.0),
            )
        })
        .collect();
    // Only a type this gateway cannot render may lack a binary form; every
    // other read skips the catalog lookup.
    let renderable = statement.columns().iter().all(|c| {
        !matches!(
            ColumnDecoder::for_type(c.type_info(), 0),
            ColumnDecoder::Unsupported(_)
        )
    });
    if renderable {
        return Ok(described(None, &statement));
    }
    match recast::text_cast_sql(tx, query, params, &columns).await {
        Ok(None) => Ok(described(None, &statement)),
        Ok(Some(wrapper)) => described_recast(tx, wrapper, &types, origin).await,
        Err(err) => Err(unpositioned(classify(err, origin, ""))),
    }
}

async fn described_recast(
    tx: &mut Transaction<'_, Postgres>,
    wrapper: String,
    types: &[PgTypeInfo],
    origin: &Origin<'_>,
) -> Result<Described, ExecError> {
    match prepare(tx, &wrapper, types).await {
        Ok(statement) => Ok(described(Some(wrapper), &statement)),
        Err(err) => Err(unpositioned(classify(err, origin, &wrapper))),
    }
}

async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    sql: &str,
    types: &[PgTypeInfo],
) -> Result<PgStatement, sqlx::Error> {
    let sql = sqlx::AssertSqlSafe(sql.to_owned()).into_sql_str();
    (&mut **tx).prepare_with(sql, types).await
}

fn described(recast: Option<String>, statement: &PgStatement) -> Described {
    let (columns, column_types) = statement
        .columns()
        .iter()
        .map(|c| (c.name().to_string(), c.type_info().name().to_string()))
        .unzip();
    Described {
        recast,
        columns,
        column_types,
    }
}

/// A position into a statement the gateway built points at nothing the
/// caller wrote.
fn unpositioned(err: ExecError) -> ExecError {
    match err {
        ExecError::Rejected(rejection) => ExecError::Rejected(rejection.with_position(None)),
        other => other,
    }
}
