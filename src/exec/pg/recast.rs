//! The second attempt at a read whose result has a column the driver
//! cannot take.
//!
//! The driver asks for every result in binary and looks every unfamiliar
//! column type up in the catalog first. Two kinds of type defeat that, and
//! with it the whole statement, before anything ran: a type with no binary
//! output function (an extension type that never wrote one), which the
//! server refuses at `Bind` (`42883`); and an internal type (category `Z`:
//! `pg_node_tree`, as in `pg_class.relpartbound`, or `pg_ndistinct` …),
//! whose catalog row the driver cannot read. Those
//! columns, and only those, are cast to `text` by wrapping the caller's
//! statement:
//!
//! ```sql
//! SELECT q.c1 AS "oid", q.c2::text AS "relacl" FROM (
//! <caller's statement>
//! ) AS q(c1, c2)
//! ```
//!
//! The wrapper reads its columns by position, so duplicate or odd output
//! names survive, and it keeps them as the column names. It runs in the same
//! read-only transaction a read always runs in; the caller's statement is
//! not changed, only nested.
//!
//! The column names and types come from a probe that returns one row of
//! NULLs. It is `EXECUTE`d over the simple protocol, the one whose result
//! description the driver does not look up — and which would run a second
//! statement smuggled into the text. So the statement is first `PREPARE`d
//! over the extended protocol, which refuses more than one: the text is
//! proven a single statement before it is ever nested. Both are prepared
//! with the caller's params' types, and the probe executes with every param
//! NULL: it reads no row, so their values do not matter. Everything runs in
//! a read-only transaction that is rolled back, tagged and guarded like the
//! read itself: `cancel_query` finds the probe, and a dropped call cancels it.

use sqlx::postgres::types::Oid;
use sqlx::{Column, Connection, Executor, PgConnection, Postgres, Transaction};

use super::super::adapter::{ExecError, effective_timeout_ms};
use super::super::query::{ExecQuery, QueryParam};
use super::super::sql_guard::{Access, statement_body};
use super::cancel::{Backend, BackendTag, CancelOnDrop};
use super::run::RunCtx;

/// SQLSTATE `42883`: what `Bind` raises for a result column whose type has
/// no binary output function. A misspelt function raises it too; that
/// statement does not prepare, and the first refusal stands.
const NO_BINARY_OUTPUT: &str = "42883";

/// Bound on the probe's statements, which plan the caller's statement but
/// read no row of it; the caller's own budget when that is shorter.
const PROBE_TIMEOUT_MS: u32 = 2_000;

/// Whether `err`, raised by `query`, may be a column the driver cannot
/// take: the server's `42883`, or the driver's own opaque failure. Reads
/// only: a write is never run twice.
pub(super) fn may_apply(err: &ExecError, query: &ExecQuery<'_>) -> bool {
    query.access == Access::ReadOnly
        && match err {
            ExecError::Rejected(rejection) => rejection.sqlstate() == NO_BINARY_OUTPUT,
            ExecError::Sql => true,
            _ => false,
        }
}

/// `query`'s statement with every column the driver cannot take cast to
/// text, or `None` when the statement does not prepare or has no such
/// column. `params` are the ones the statement will run with.
pub(super) async fn text_cast_sql(
    conn: &mut PgConnection,
    ctx: &RunCtx<'_>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
) -> Option<String> {
    let mut tx = conn.begin().await.ok()?;
    let wrapped = guarded_probe(&mut tx, ctx, query, params).await;
    // Read-only and nothing to keep; a failed rollback is the release
    // hook's to clean up (`release`).
    let _ = tx.rollback().await;
    wrapped
}

/// The probe under the same tag, budget and drop guard as a read of
/// `query`. The interpolated values are a number and a [`BackendTag`],
/// which contains no quote.
async fn guarded_probe(
    tx: &mut Transaction<'_, Postgres>,
    ctx: &RunCtx<'_>,
    query: &ExecQuery<'_>,
    params: &[QueryParam],
) -> Option<String> {
    let tag = BackendTag::for_request(query.request_id);
    let ms = effective_timeout_ms(query.statement_timeout_ms).min(PROBE_TIMEOUT_MS);
    let setup = format!(
        "SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = {ms}; \
         SET LOCAL application_name = '{}'; \
         SET LOCAL standard_conforming_strings = on",
        tag.as_str()
    );
    tx.execute(sqlx::AssertSqlSafe(setup)).await.ok()?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .persistent(false)
        .fetch_one(&mut **tx)
        .await
        .ok()?;
    let mut cancel = CancelOnDrop::armed(
        ctx.cancel_pool.clone(),
        Backend { pid, tag },
        ctx.detached.clone(),
    );
    let wrapped = match statement_body(query.sql) {
        Some(body) => probe(tx, body, params).await,
        None => None,
    };
    cancel.disarm();
    wrapped
}

async fn probe(
    tx: &mut Transaction<'_, Postgres>,
    body: &str,
    params: &[QueryParam],
) -> Option<String> {
    let types = param_types(params);
    // Extended protocol: a second statement in `body` is refused here.
    prepare(tx, &format!("PREPARE dbmcp_recast{types} AS\n{body}")).await?;
    tx.execute("DEALLOCATE dbmcp_recast").await.ok()?;
    prepare(
        tx,
        &format!(
            "PREPARE dbmcp_probe{types} AS SELECT q.* FROM (SELECT 1) AS one LEFT JOIN \
             (SELECT * FROM (\n{body}\n) AS s LIMIT 0) AS q ON true"
        ),
    )
    .await?;
    let row = (&mut **tx)
        .fetch_optional(sqlx::AssertSqlSafe(execute_with_nulls(
            "dbmcp_probe",
            params.len(),
        )))
        .await
        .ok()??;
    tx.execute("DEALLOCATE dbmcp_probe").await.ok()?;
    let columns: Vec<(String, u32)> = sqlx::Row::columns(&row)
        .iter()
        .map(|c| {
            (
                c.name().to_string(),
                c.type_info().oid().map_or(0, |oid| oid.0),
            )
        })
        .collect();
    let oids: Vec<u32> = columns.iter().map(|(_, oid)| *oid).collect();
    let textless = untakeable(tx, &oids).await?;
    if textless.is_empty() {
        return None;
    }
    let columns: Vec<(&str, bool)> = columns
        .iter()
        .map(|(name, oid)| (name.as_str(), textless.contains(oid)))
        .collect();
    Some(wrap(body, &columns))
}

async fn prepare(tx: &mut Transaction<'_, Postgres>, sql: &str) -> Option<()> {
    let statement = sqlx::query(sqlx::AssertSqlSafe(sql)).persistent(false);
    statement.execute(&mut **tx).await.ok().map(drop)
}

/// The `PREPARE` type list for the types `params` run with (see
/// [`QueryParam`]), empty without params. Every name is a constant.
pub(super) fn param_types(params: &[QueryParam]) -> String {
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

/// `EXECUTE name` with `count` NULL arguments.
pub(super) fn execute_with_nulls(name: &str, count: usize) -> String {
    match count {
        0 => format!("EXECUTE {name}"),
        _ => format!("EXECUTE {name}({})", vec!["NULL"; count].join(", ")),
    }
}

/// Which of `types` the driver cannot take, themselves or as an array's
/// element. The OIDs are numbers, so they are interpolated, not bound.
async fn untakeable(tx: &mut Transaction<'_, Postgres>, types: &[u32]) -> Option<Vec<u32>> {
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
        .await
        .ok()?;
    Some(found.into_iter().map(|oid| oid.0).collect())
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
