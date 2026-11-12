//! AST-level guard for SQL sent to a target DB. Defense in depth on top of the
//! Postgres role's privileges — if a DBA accidentally grants a role more than
//! its grant's action warrants, the gateway still refuses to send the query.
//!
//! Two access levels, selected by the caller's authz decision:
//!
//! - [`Access::ReadOnly`] (the `query_read` default) accepts only:
//!   - a single `SELECT` (with or without CTEs), recursively read-only
//!   - a single non-`ANALYZE` `EXPLAIN` wrapping one of the above
//! - [`Access::ReadWrite`] (requires a `query_write` grant) additionally
//!   accepts a single top-level `INSERT` / `UPDATE` / `DELETE` — **data
//!   writes only**. Schema modification stays blocked in *both* modes:
//!   `CREATE` / `ALTER` / `DROP` / `TRUNCATE`, `GRANT` / `REVOKE`, `COPY`,
//!   transaction control, and multiple statements are always rejected. A
//!   write's read positions (its source `SELECT`, `VALUES`, `WHERE`,
//!   assignments, `RETURNING`) are still walked for the denied
//!   filesystem/network functions.
//!
//! Anything not explicitly recognised — a write hidden in a CTE or subquery,
//! `SELECT ... FOR UPDATE/SHARE`, `SELECT ... INTO`, `EXPLAIN ANALYZE` in
//! either spelling (`ANALYZE` keyword or `(ANALYZE)` option — both execute)
//! — is rejected with a typed error. Conservative on purpose: better
//! to reject a legitimate exotic statement than quietly send an unintended one.
//!
//! ## Substructure walk
//!
//! Beyond the top-level statement-shape check, denied-function lookups and
//! nested-write / lock / `SELECT INTO` detection go through sqlparser's
//! [`Visitor`] trait (the `visitor` feature). The `Visit` derive on every
//! AST node walks every child node automatically, so a callback registered on
//! `Expr` fires for expressions in every position sqlparser knows about
//! (`EXISTS`, `ANY`/`ALL`, tuples, arrays, `FILTER`, window frames, `QUALIFY`,
//! `UNNEST`, `GROUPING SETS`/`ROLLUP`/`CUBE`, `IS DISTINCT FROM`, `substring`
//! / `trim` / `overlay` / …, and any node a future sqlparser bump adds). The
//! previous hand-rolled recursion missed each of those positions until they
//! were manually enumerated — that's the class of gap this module exists to
//! close, and the reason the walk is now visitor-driven, not hand-recursion.

mod shape;
mod visitor;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

use sqlparser::ast::{Statement, UtilityOption, Visit};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use std::ops::ControlFlow;

use shape::check_statement_shape;
use visitor::GuardVisitor;

/// How much a query is allowed to do, decided upstream by the caller's grant
/// (`query_read` → [`Access::ReadOnly`]; `query_write` → [`Access::ReadWrite`]).
/// Only ever *widens* the read-only baseline to permit data writes — never
/// relaxes the schema-modification or denied-function guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("could not parse SQL")]
    Parse,
    #[error("multiple statements are not allowed (got {0})")]
    MultiStatement(usize),
    #[error("statement type `{0}` is not allowed; only SELECT and EXPLAIN")]
    NotAllowed(&'static str),
    #[error("SELECT ... FOR UPDATE/SHARE is not allowed (acquires write locks)")]
    Locking,
    #[error("write statement `{0}` is not allowed inside a read-only query")]
    WriteInReadPath(&'static str),
    #[error("SELECT ... INTO is not allowed (it materializes a table)")]
    SelectInto,
    #[error("EXPLAIN ANALYZE is not allowed (it executes the query)")]
    ExplainAnalyze,
    /// Stable error code: `GUARD_DENIED_FUNCTION`.
    #[error("function `{0}` is not allowed (high-privilege server-side function)")]
    DeniedFunction(&'static str),
}

/// Read-only guard — the `query_read` default. Equivalent to
/// `check_sql(sql, Access::ReadOnly)`.
pub fn is_read_only(sql: &str) -> Result<(), GuardError> {
    check_sql(sql, Access::ReadOnly)
}

/// SQL text that passed [`is_read_only`]. [`ReadOnlySql::parse`] is the only
/// constructor, so holding one proves the read-only guard already ran — the
/// exec layer's `explain` takes this instead of a bare `&str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOnlySql<'a>(&'a str);

impl<'a> ReadOnlySql<'a> {
    pub fn parse(sql: &'a str) -> Result<Self, GuardError> {
        is_read_only(sql)?;
        Ok(Self(sql))
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

/// Parse `sql` and enforce the guard at the given [`Access`] level. A single
/// statement only — multiple statements are rejected in both modes so a write
/// can never ride in behind a leading `SELECT`.
pub fn check_sql(sql: &str, access: Access) -> Result<(), GuardError> {
    let dialect = PostgreSqlDialect {};
    let statements = Parser::parse_sql(&dialect, sql).map_err(|e| match e {
        ParserError::ParserError(_)
        | ParserError::TokenizerError(_)
        | ParserError::RecursionLimitExceeded => GuardError::Parse,
    })?;

    match statements.len() {
        0 => return Err(GuardError::Parse),
        1 => {}
        n => return Err(GuardError::MultiStatement(n)),
    }

    // Unwrap `EXPLAIN` wrappers so shape and visitor operate on the actual
    // target statement. ANALYZE — in either spelling — executes the wrapped
    // statement, so it fails fast here before any further inspection.
    let mut stmt: &Statement = &statements[0];
    while let Statement::Explain {
        analyze,
        options,
        statement,
        ..
    } = stmt
    {
        if explain_analyzes(*analyze, options.as_deref()) {
            return Err(GuardError::ExplainAnalyze);
        }
        stmt = statement;
    }

    check_statement_shape(stmt, access)?;

    match stmt.visit(&mut GuardVisitor::new()) {
        ControlFlow::Continue(()) => Ok(()),
        ControlFlow::Break(e) => Err(e),
    }
}

/// Whether an `EXPLAIN` carries `ANALYZE` — i.e. whether Postgres will actually
/// *run* the statement instead of only planning it.
///
/// Postgres accepts the flag two ways and sqlparser models them differently:
/// the bare keyword form (`EXPLAIN ANALYZE …`) sets `analyze`, while the
/// parenthesised form (`EXPLAIN (ANALYZE, FORMAT JSON) …`) leaves `analyze`
/// false and lands the flag in `options`. Both execute; both must be caught.
///
/// An explicit `(ANALYZE false)` is rejected too: the guard does not interpret
/// option arguments, and there is no reason to write that form.
fn explain_analyzes(analyze: bool, options: Option<&[UtilityOption]>) -> bool {
    analyze
        || options.is_some_and(|opts| {
            opts.iter()
                .any(|opt| opt.name.value.eq_ignore_ascii_case("analyze"))
        })
}
