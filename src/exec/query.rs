//! Per-call inputs to [`super::DbAdapter`]. Every query carries the gateway
//! `request_id` it runs for: the Postgres adapter tags the backend with it
//! (`application_name`), which is what `db_activity` reports and
//! `cancel_request` targets.

use uuid::Uuid;

use super::ident::Identifier;
use super::sql_guard::{Access, GuardedSql};

/// A single query against the adapter. `binds` are positional text values
/// applied in order — `$1`, `$2`, … for pg; future adapters define their own
/// placeholder convention. `binds = &[]` for queries with no parameters.
///
/// `access` is the caller's authz decision, and the adapter enforces it at
/// the database: [`Access::ReadOnly`] runs as the database's read `role`
/// inside a read-only transaction; only a `query_write` grant may pass
/// [`Access::ReadWrite`], which runs as its `write_role`.
///
/// `dry_run` rolls the transaction back instead of committing it: a write
/// runs to completion, reports `rows_affected`, and leaves no change.
#[derive(Debug)]
pub struct ExecQuery<'a> {
    pub sql: &'a str,
    pub binds: &'a [&'a str],
    pub statement_timeout_ms: Option<u32>,
    pub row_limit: u32,
    pub access: Access,
    pub dry_run: bool,
    pub request_id: Uuid,
}

/// Catalog lookup for one schema, optionally narrowed to one table. Schema
/// and table are *values* to the catalog query (bound, not interpolated).
/// Mongo ignores `schema` (the database is the namespace) and reads `table`
/// as a collection name.
#[derive(Debug)]
pub struct SchemaQuery<'a> {
    pub schema: &'a str,
    pub table: Option<&'a str>,
    pub statement_timeout_ms: Option<u32>,
    pub row_limit: u32,
    pub request_id: Uuid,
}

/// First `row_limit` rows of one table, every column. The names are
/// [`Identifier`]s because they land in generated SQL as identifiers. Mongo
/// samples the collection named `table`.
#[derive(Debug)]
pub struct SampleQuery<'a> {
    pub schema: Identifier<'a>,
    pub table: Identifier<'a>,
    pub statement_timeout_ms: Option<u32>,
    pub row_limit: u32,
    pub request_id: Uuid,
}

/// The plan of one guarded statement. Plain `EXPLAIN` never executes, so a
/// data write may be explained (under the write role, still inside a
/// read-only transaction). `analyze` executes the statement and is refused
/// unless [`GuardedSql::required_access`] is [`Access::ReadOnly`].
#[derive(Debug)]
pub struct ExplainQuery<'a> {
    pub sql: GuardedSql<'a>,
    pub analyze: bool,
    pub statement_timeout_ms: Option<u32>,
    pub request_id: Uuid,
}

/// Size and maintenance statistics for the tables of one schema (or one
/// table) that the read role may `SELECT` from.
#[derive(Debug)]
pub struct TableStatsQuery<'a> {
    pub schema: &'a str,
    pub table: Option<&'a str>,
    pub statement_timeout_ms: Option<u32>,
    pub row_limit: u32,
    pub request_id: Uuid,
}

/// The gateway's own running statements on one database.
#[derive(Debug)]
pub struct ActivityQuery {
    pub statement_timeout_ms: Option<u32>,
    pub row_limit: u32,
    pub request_id: Uuid,
}
