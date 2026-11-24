//! The second attempt at a read whose result has a column the driver
//! cannot take.
//!
//! The driver asks for every result in binary and looks every unfamiliar
//! column type up in the catalog first. Two kinds of type defeat that, and
//! with it the whole statement, before anything ran: a type with no binary
//! output function (`aclitem` — so `SELECT * FROM pg_class` — or an
//! extension type that never wrote one), which the server refuses at `Bind`
//! (`42883`); and an internal type (category `Z`: `pg_node_tree`,
//! `pg_ndistinct` …), whose catalog row the driver cannot read. Those
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
//! NULLs. It runs over the simple protocol, the one whose result description
//! the driver does not look up — and which would run a second statement
//! smuggled into the text. So the statement is first `PREPARE`d over the
//! extended protocol, which refuses more than one: the text is proven a
//! single statement before it is ever nested. Everything runs in a
//! read-only transaction that is rolled back.

use sqlx::postgres::types::Oid;
use sqlx::{Column, Connection, Executor, PgConnection, Postgres, Transaction};

use super::super::adapter::ExecError;
use super::super::query::ExecQuery;
use super::super::sql_guard::Access;

/// SQLSTATE `42883`: what `Bind` raises for a result column whose type has
/// no binary output function. A misspelt function raises it too; that
/// statement does not prepare, and the first refusal stands.
const NO_BINARY_OUTPUT: &str = "42883";

/// Bound on the probe's statements, which plan the caller's statement but
/// read no row of it.
const PROBE_SETUP: &str = "SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = 2000";

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

/// `sql` with every column the driver cannot take cast to text, or `None`
/// when the statement does not prepare or has no such column.
pub(super) async fn text_cast_sql(conn: &mut PgConnection, sql: &str) -> Option<String> {
    let body = statement_body(sql);
    let mut tx = conn.begin().await.ok()?;
    let wrapped = probe(&mut tx, body).await;
    // Read-only and nothing to keep; a failed rollback is the release
    // hook's to clean up (`release`).
    let _ = tx.rollback().await;
    wrapped
}

async fn probe(tx: &mut Transaction<'_, Postgres>, body: &str) -> Option<String> {
    tx.execute(PROBE_SETUP).await.ok()?;
    // Extended protocol: a second statement in `body` is refused here.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "PREPARE dbmcp_recast AS\n{body}"
    )))
    .persistent(false)
    .execute(&mut **tx)
    .await
    .ok()?;
    tx.execute("DEALLOCATE dbmcp_recast").await.ok()?;
    let probe = format!(
        "SELECT q.* FROM (SELECT 1) AS one LEFT JOIN \
         (SELECT * FROM (\n{body}\n) AS s LIMIT 0) AS q ON true"
    );
    let row = (&mut **tx)
        .fetch_optional(sqlx::AssertSqlSafe(probe))
        .await
        .ok()??;
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

/// A trailing `;` ends a statement but not a subquery.
fn statement_body(sql: &str) -> &str {
    let body = sql.trim_end();
    body.strip_suffix(';').unwrap_or(body)
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
mod tests {
    use super::*;
    use crate::exec::rejection::DbRejection;

    #[test]
    fn only_the_columns_without_binary_form_are_cast() {
        let wrapped = wrap(
            statement_body("SELECT oid, relacl, relname FROM pg_class -- all;\n ; "),
            &[("oid", false), ("relacl", true), ("rel\"name", false)],
        );
        assert_eq!(
            wrapped,
            "SELECT q.c1 AS \"oid\", q.c2::text AS \"relacl\", q.c3 AS \"rel\"\"name\" FROM (\n\
             SELECT oid, relacl, relname FROM pg_class -- all;\n \n) AS q(c1, c2, c3)"
        );
    }

    #[test]
    fn only_a_read_refused_for_a_missing_function_is_tried_again() {
        let rejected = |code| ExecError::Rejected(DbRejection::new(code, "", ""));
        let mut query = ExecQuery {
            sql: "SELECT relacl FROM pg_class",
            binds: &[],
            statement_timeout_ms: None,
            row_limit: 1,
            access: Access::ReadOnly,
            dry_run: false,
            request_id: uuid::Uuid::nil(),
        };
        assert!(may_apply(&rejected(NO_BINARY_OUTPUT), &query));
        assert!(!may_apply(&rejected("42601"), &query));
        assert!(may_apply(&ExecError::Sql, &query));
        assert!(!may_apply(&ExecError::Timeout, &query));
        query.access = Access::ReadWrite;
        assert!(!may_apply(&rejected(NO_BINARY_OUTPUT), &query));
    }
}
