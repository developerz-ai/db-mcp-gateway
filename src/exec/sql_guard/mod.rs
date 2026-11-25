//! AST-level guard for SQL sent to a target DB — the third layer of read-only
//! enforcement. The DB role's privileges are the first; the read-only
//! transaction every read runs in (`exec::pg::run`) is the second, and holds
//! even if a DBA grants the role more than its grant's action warrants. The
//! guard refuses what neither of those stops (session-state and filesystem
//! functions, dynamic SQL) and gives a typed error before the query is sent.
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
//! any spelling (`ANALYZE` keyword or `(ANALYZE)` / `(ANALYSE)` option — all
//! execute) — is rejected with a typed error, as is text Postgres lexes
//! differently from sqlparser: a Unicode-escaped identifier (`U&"…"`), or
//! any text the two split into different tokens (`lexical`, `pg_scan`).
//! A relation showing other sessions' statements is refused by name.
//! The statement's length and structure are bounded first (`bounds`), the work
//! its parse may take with them (`budget`), and its
//! lexemes are held against the denylist whatever the tree holds (`tokens`).
//! Conservative on purpose: better to reject a legitimate exotic statement
//! than quietly send an unintended one.
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

mod bounds;
mod budget;
mod denylist;
mod error;
mod lexical;
mod metered;
mod parse;
mod pg_scan;
mod shape;
mod tokens;
mod visitor;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;

use sqlparser::ast::{Statement, Visit};
use std::ops::ControlFlow;

pub use error::{GuardError, SqlLocation};

use bounds::{check_bounds, check_length, off_the_worker, with_parser_stack};
use lexical::check_lexical;
use parse::parse;
use shape::{check_statement_shape, explain_analyzes, required_access};
use tokens::check_tokens;
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

/// Read-only guard — the `query_read` default. Equivalent to
/// `check_sql(sql, Access::ReadOnly)`.
pub fn is_read_only(sql: &str) -> Result<(), GuardError> {
    check_sql(sql, Access::ReadOnly)
}

/// SQL text that passed the guard, plus the access the statement itself
/// needs: [`Access::ReadOnly`] for a `SELECT`, [`Access::ReadWrite`] for a
/// data write. [`GuardedSql::parse`] is the only constructor, so holding one
/// proves the guard already ran — the exec layer's `explain` takes this
/// instead of a bare `&str`, and picks the role and the `ANALYZE` rule from
/// [`GuardedSql::required_access`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardedSql<'a> {
    sql: &'a str,
    required: Access,
}

impl<'a> GuardedSql<'a> {
    /// Guard `sql` at the caller's `access` (its grant). A `query_read`
    /// caller can only ever obtain a read statement.
    pub fn parse(sql: &'a str, access: Access) -> Result<Self, GuardError> {
        let required = guard(sql, access)?;
        Ok(Self { sql, required })
    }

    pub fn as_str(&self) -> &'a str {
        self.sql
    }

    /// The least access the statement needs: never wider than the `access`
    /// it was parsed under.
    pub fn required_access(&self) -> Access {
        self.required
    }
}

/// Parse `sql` and enforce the guard at the given [`Access`] level. A single
/// statement only — multiple statements are rejected in both modes so a write
/// can never ride in behind a leading `SELECT`.
pub fn check_sql(sql: &str, access: Access) -> Result<(), GuardError> {
    guard(sql, access).map(|_| ())
}

/// [`check_sql`], returning the access the admitted statement needs.
fn guard(sql: &str, access: Access) -> Result<Access, GuardError> {
    check_length(sql)?;
    off_the_worker(sql.len(), || guard_here(sql, access))
}

fn guard_here(sql: &str, access: Access) -> Result<Access, GuardError> {
    let lexemes = check_lexical(sql)?;
    check_bounds(sql, &lexemes)?;
    let required = with_parser_stack(|| inspect(sql, access))?;
    check_tokens(sql, &lexemes)?;
    Ok(required)
}

/// Parse, walk and drop the tree: sqlparser work only, and all of it, so no
/// part of a tree — partial or refused — outlives the stack sized for it.
fn inspect(sql: &str, access: Access) -> Result<Access, GuardError> {
    let statements = parse(sql)?;
    match statements.len() {
        0 => return Err(GuardError::Parse(None)),
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
        ControlFlow::Continue(()) => Ok(required_access(stmt)),
        ControlFlow::Break(e) => Err(e),
    }
}

/// `sql` from its first token to the end of its last, leading and
/// terminating `;`s dropped: the text that nests as a subquery. Read off
/// Postgres's own token boundaries, so a comment after the `;` (`… ; --
/// note`) cannot hide it, and a `;` inside a string or comment is never
/// taken for it. `None` when the text does not scan (the guard has then
/// refused it already) or holds no statement.
pub(crate) fn statement_body(sql: &str) -> Option<&str> {
    let lexemes = pg_scan::scan(sql).ok()?;
    // Lexemes that are nothing but `;` are skipped at both ends, and the
    // `;`s at the edge of the first and last that are not (adjacent symbols
    // merge, as in `);` or `;(`).
    let text = |lexeme: &pg_scan::Lexeme| &sql[lexeme.start..lexeme.end];
    let is_symbols = |lexeme: &pg_scan::Lexeme| matches!(lexeme.kind, pg_scan::Kind::Symbols);
    let trimmed = |lexeme: &pg_scan::Lexeme| {
        if is_symbols(lexeme) {
            text(lexeme).trim_matches(';').len()
        } else {
            lexeme.end - lexeme.start
        }
    };
    let first = lexemes.iter().find(|lexeme| trimmed(lexeme) > 0)?;
    let last = lexemes.iter().rev().find(|lexeme| trimmed(lexeme) > 0)?;
    let start = if is_symbols(first) {
        first.end - text(first).trim_start_matches(';').len()
    } else {
        first.start
    };
    let end = if is_symbols(last) {
        last.start + text(last).trim_end_matches(';').len()
    } else {
        last.end
    };
    sql.get(start..end)
}
