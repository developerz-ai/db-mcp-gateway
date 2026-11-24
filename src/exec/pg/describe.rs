//! Column names and types for a zero-row read. Without them the caller
//! cannot tell "your filter matched nothing" from "that table has no such
//! columns" (#136). Nothing runs again: only Parse/Describe.
//!
//! Without params the statement itself is described. With params, a bare
//! Describe would re-infer every placeholder's type from the text alone,
//! and `SELECT $1 AS v` has none: the statement is `PREPARE`d with the
//! types the read was bound with (refusing a second statement, like the
//! read's own Parse), and `EXECUTE` of it is described — Postgres answers
//! that with the prepared result's columns, without executing it. The
//! driver can only describe through a named statement; `reset_on_release`
//! closes it, and `DEALLOCATE ALL` anything prepared here, before the
//! connection serves anyone else.

use std::time::Duration;

use sqlx::{Column, Executor, Postgres, SqlSafeStr, Transaction, TypeInfo};

use super::super::query::QueryParam;
use super::super::sql_guard::statement_body;
use super::recast::{execute_with_nulls, param_types};

const PREPARED: &str = "dbmcp_describe";

/// `(names, types)`, best-effort on purpose: the read already succeeded,
/// so a failure here answers no columns, never an error. `None` means
/// `budget` ran out with the lookup still in flight on the connection.
pub(super) async fn describe_columns(
    tx: &mut Transaction<'_, Postgres>,
    sql: &str,
    params: &[QueryParam],
    budget: Duration,
) -> Option<(Vec<String>, Vec<String>)> {
    let described = tokio::time::timeout(budget, describe(tx, sql, params))
        .await
        .ok()?;
    Some(described.unwrap_or_default())
}

async fn describe(
    tx: &mut Transaction<'_, Postgres>,
    sql: &str,
    params: &[QueryParam],
) -> Option<(Vec<String>, Vec<String>)> {
    if params.is_empty() {
        return columns_of(tx, sql.to_owned()).await;
    }
    let body = statement_body(sql)?;
    let prepare = format!("PREPARE {PREPARED}{} AS\n{body}", param_types(params));
    sqlx::query(sqlx::AssertSqlSafe(prepare))
        .persistent(false)
        .execute(&mut **tx)
        .await
        .ok()?;
    let columns = columns_of(tx, execute_with_nulls(PREPARED, params.len())).await;
    let deallocate = format!("DEALLOCATE {PREPARED}");
    tx.execute(sqlx::AssertSqlSafe(deallocate)).await.ok()?;
    columns
}

async fn columns_of(
    tx: &mut Transaction<'_, Postgres>,
    sql: String,
) -> Option<(Vec<String>, Vec<String>)> {
    let described = (&mut **tx)
        .describe(sqlx::AssertSqlSafe(sql).into_sql_str())
        .await
        .ok()?;
    Some(
        described
            .columns()
            .iter()
            .map(|c| (c.name().to_string(), c.type_info().name().to_string()))
            .unzip(),
    )
}
