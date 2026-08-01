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
//! were manually enumerated — that's the class of gap this file exists to
//! close, and the reason the walk is now visitor-driven, not hand-recursion.

use sqlparser::ast::{
    Expr, ObjectName, OnInsert, Query, SetExpr, Statement, TableFactor, UtilityOption, Visit,
    Visitor,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use std::ops::ControlFlow;

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

/// Functions that the gateway always blocks, regardless of the Postgres role's
/// privileges. These access the server filesystem or trigger network I/O —
/// primary data-exfiltration / credential-theft vectors:
///
/// - `pg_read_file` / `pg_read_binary_file` — read arbitrary server-side files
///   (e.g. `pg_hba.conf`, `.pgpass`). A read-only role that is accidentally
///   granted execute on these can exfiltrate credentials without any writes.
/// - `pg_ls_dir` / `pg_stat_file` — enumerate and stat server filesystem paths;
///   information-gathering step for targeted file reads.
/// - `lo_export` — writes a large object to a server-side path (filesystem write
///   from inside a SELECT body — the read-only role boundary does not stop it if
///   execute is granted).
/// - `lo_import` — reads a file into a large object; symmetric to `lo_export`.
const DENIED_FUNCTIONS: &[&str] = &[
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_export",
    "lo_import",
];

/// Read-only guard — the `query_read` default. Equivalent to
/// `check_sql(sql, Access::ReadOnly)`.
pub fn is_read_only(sql: &str) -> Result<(), GuardError> {
    check_sql(sql, Access::ReadOnly)
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

/// Whether `stmt` is a statement type the guard admits at all under `access`.
/// The substructure — nested writes, locking clauses, `SELECT INTO`, denied
/// functions — is enforced by [`GuardVisitor`] afterwards. Explains have been
/// unwrapped by [`check_sql`].
fn check_statement_shape(stmt: &Statement, access: Access) -> Result<(), GuardError> {
    match stmt {
        // Data writes are admitted under ReadWrite; the visitor still walks
        // their read positions for denied functions and writable-CTE hazards.
        // The ON clause is checked here so an unrecognised `OnInsert` variant
        // (added in a future sqlparser bump) is denied by default rather than
        // waved through with its inner fields un-inspected.
        Statement::Insert(insert) if access == Access::ReadWrite => {
            check_on_insert(insert.on.as_ref())
        }
        Statement::Update { .. } if access == Access::ReadWrite => Ok(()),
        Statement::Delete(_) if access == Access::ReadWrite => Ok(()),

        Statement::Query(_) => Ok(()),
        Statement::ExplainTable { .. } => Ok(()), // `\d table` analog; read-only.

        // Explicit rejections so the error message names the family, rather
        // than the generic "unsupported" that the catch-all below emits.
        Statement::Insert { .. } => Err(GuardError::NotAllowed("INSERT")),
        Statement::Update { .. } => Err(GuardError::NotAllowed("UPDATE")),
        Statement::Delete { .. } => Err(GuardError::NotAllowed("DELETE")),
        Statement::Truncate { .. } => Err(GuardError::NotAllowed("TRUNCATE")),
        Statement::Drop { .. } => Err(GuardError::NotAllowed("DROP")),
        Statement::CreateTable { .. } => Err(GuardError::NotAllowed("CREATE TABLE")),
        Statement::CreateView { .. } => Err(GuardError::NotAllowed("CREATE VIEW")),
        Statement::CreateIndex { .. } => Err(GuardError::NotAllowed("CREATE INDEX")),
        Statement::CreateSchema { .. } => Err(GuardError::NotAllowed("CREATE SCHEMA")),
        Statement::CreateDatabase { .. } => Err(GuardError::NotAllowed("CREATE DATABASE")),
        Statement::CreateFunction { .. } => Err(GuardError::NotAllowed("CREATE FUNCTION")),
        Statement::CreateRole { .. } => Err(GuardError::NotAllowed("CREATE ROLE")),
        Statement::AlterTable { .. } => Err(GuardError::NotAllowed("ALTER TABLE")),
        Statement::Grant { .. } => Err(GuardError::NotAllowed("GRANT")),
        Statement::Revoke { .. } => Err(GuardError::NotAllowed("REVOKE")),
        Statement::StartTransaction { .. } => Err(GuardError::NotAllowed("BEGIN/START")),
        Statement::Commit { .. } => Err(GuardError::NotAllowed("COMMIT")),
        Statement::Rollback { .. } => Err(GuardError::NotAllowed("ROLLBACK")),
        Statement::SetTransaction { .. } => Err(GuardError::NotAllowed("SET TRANSACTION")),
        Statement::SetVariable { .. } => Err(GuardError::NotAllowed("SET")),
        Statement::Copy { .. } => Err(GuardError::NotAllowed("COPY")),
        _ => Err(GuardError::NotAllowed("unsupported")),
    }
}

/// Deny-by-default match on the ON clause of an `INSERT` — the two shapes the
/// guard understands are walked normally by the visitor; anything else (an
/// `OnInsert` variant added in a future sqlparser bump) is rejected so its
/// inner fields cannot slip past unexamined.
fn check_on_insert(on: Option<&OnInsert>) -> Result<(), GuardError> {
    match on {
        None => Ok(()),
        Some(OnInsert::DuplicateKeyUpdate(_) | OnInsert::OnConflict(_)) => Ok(()),
        _ => Err(GuardError::NotAllowed("unsupported ON clause")),
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

/// Substructure guard, run once the top-level [`check_statement_shape`] has
/// admitted the statement. Enforces four things via sqlparser's `Visit`
/// derive, which walks every child node automatically:
///
/// 1. Denied-function calls (`Expr::Function`, and `TableFactor::{Table,
///    Function}` when a set-returning denied function is used as a table
///    source).
/// 2. `SELECT ... FOR UPDATE / FOR SHARE` — [`GuardError::Locking`].
/// 3. `SELECT ... INTO new_table` — [`GuardError::SelectInto`].
/// 4. Nested `Statement` — sqlparser encodes a writable CTE as a Query whose
///    body is `SetExpr::Insert(Statement)`, so any `pre_visit_statement`
///    firing *after* the top level is a write hiding in a read path.
///
/// Because every expression, query, and table-factor position is walked by
/// the derive, this needs no per-variant enumeration and cannot silently miss
/// a node type a future sqlparser bump adds.
struct GuardVisitor {
    top_seen: bool,
}

impl GuardVisitor {
    fn new() -> Self {
        Self { top_seen: false }
    }
}

impl Visitor for GuardVisitor {
    type Break = GuardError;

    fn pre_visit_statement(&mut self, stmt: &Statement) -> ControlFlow<GuardError> {
        if !self.top_seen {
            self.top_seen = true;
            return ControlFlow::Continue(());
        }
        let kind = match stmt {
            Statement::Insert(_) => "INSERT",
            Statement::Update { .. } => "UPDATE",
            Statement::Delete(_) => "DELETE",
            // Any other nested statement type (implausible in a real query,
            // but syntactically expressible) is deny-by-default rather than
            // leave the caller wondering which read position it slipped past.
            _ => return ControlFlow::Break(GuardError::NotAllowed("nested statement")),
        };
        ControlFlow::Break(GuardError::WriteInReadPath(kind))
    }

    fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<GuardError> {
        // Read-only roles cannot take these locks anyway, so Postgres would
        // return a cryptic "permission denied" — reject with a typed error
        // here instead.
        if !q.locks.is_empty() {
            return ControlFlow::Break(GuardError::Locking);
        }
        // `SELECT ... INTO` lives on `Select.into`; the visitor has no
        // callback for `Select` or `SetExpr`, so inspect this Query's body
        // directly. Nested Queries are covered by their own pre_visit_query.
        if body_has_select_into(q.body.as_ref()) {
            return ControlFlow::Break(GuardError::SelectInto);
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<GuardError> {
        if let Expr::Function(f) = expr {
            if let Err(err) = check_denied_name(&f.name) {
                return ControlFlow::Break(err);
            }
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<GuardError> {
        // `FROM pg_ls_dir(...)` and `FROM LATERAL pg_ls_dir(...)` place the
        // denied name on a TableFactor, not an Expr::Function — check both
        // shapes here so it is caught symmetrically with the expression pass.
        let name = match tf {
            TableFactor::Table { name, .. } | TableFactor::Function { name, .. } => name,
            _ => return ControlFlow::Continue(()),
        };
        if let Err(err) = check_denied_name(name) {
            return ControlFlow::Break(err);
        }
        ControlFlow::Continue(())
    }
}

/// Whether a query body directly contains a `SELECT ... INTO`. Recurses only
/// through `SetOperation` branches (each is a `SetExpr`, not a `Query`, so
/// the visitor's `pre_visit_query` does not fire on them). Nested
/// `SetExpr::Query` is walked by the outer visitor instead.
fn body_has_select_into(body: &SetExpr) -> bool {
    match body {
        SetExpr::Select(s) => s.into.is_some(),
        SetExpr::SetOperation { left, right, .. } => {
            body_has_select_into(left) || body_has_select_into(right)
        }
        _ => false,
    }
}

/// Match a callable's name against the denylist. Matches on the last identifier
/// component so schema-qualified calls (`pg_catalog.pg_read_file(...)`) are
/// caught too. Case-insensitive to match SQL identifier semantics.
fn check_denied_name(name: &ObjectName) -> Result<(), GuardError> {
    let fn_name = name.0.last().map(|i| i.value.as_str()).unwrap_or("");
    match DENIED_FUNCTIONS
        .iter()
        .find(|&&d| d.eq_ignore_ascii_case(fn_name))
    {
        Some(&denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(sql: &str) {
        assert!(
            is_read_only(sql).is_ok(),
            "expected `{sql}` to be allowed, got {:?}",
            is_read_only(sql)
        );
    }

    fn rejected(sql: &str, want: GuardError) {
        let got = is_read_only(sql);
        assert_eq!(
            got,
            Err(want.clone()),
            "expected `{sql}` rejected as {want:?}, got {got:?}"
        );
    }

    fn rejected_not_allowed(sql: &str, kind: &str) {
        match is_read_only(sql) {
            Err(GuardError::NotAllowed(got)) => assert_eq!(got, kind, "for `{sql}`"),
            other => panic!("expected NotAllowed({kind}) for `{sql}`, got {other:?}"),
        }
    }

    #[test]
    fn plain_selects_allowed() {
        ok("SELECT 1");
        ok("SELECT id, email FROM users");
        ok("SELECT * FROM users WHERE id = 1");
        ok("SELECT a, b FROM t ORDER BY a LIMIT 10");
        ok("SELECT now()");
    }

    #[test]
    fn ctes_allowed() {
        ok("WITH x AS (SELECT 1) SELECT * FROM x");
        ok(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 5) SELECT * FROM n",
        );
    }

    #[test]
    fn explain_wrapping_select_allowed() {
        ok("EXPLAIN SELECT 1");
        ok("EXPLAIN (FORMAT JSON) SELECT * FROM users");
    }

    #[test]
    fn explain_analyze_rejected() {
        // ANALYZE *executes* the target, so it must not reach the DB — even when
        // the target is a plain SELECT, and especially for a writable CTE.
        rejected("EXPLAIN ANALYZE SELECT 1", GuardError::ExplainAnalyze);
        rejected(
            "EXPLAIN ANALYZE WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            GuardError::ExplainAnalyze,
        );
    }

    /// The parenthesised utility-option form is the *other* spelling of the same
    /// flag, and it is the one the Postgres dialect parses into `options` with
    /// `analyze: false` — so a keyword-only check lets it through and the DB
    /// runs the query in full, row cap and all bypassed.
    #[test]
    fn explain_with_analyze_utility_option_rejected() {
        rejected("EXPLAIN (ANALYZE) SELECT 1", GuardError::ExplainAnalyze);
        rejected(
            "EXPLAIN (ANALYZE, FORMAT JSON) SELECT 1",
            GuardError::ExplainAnalyze,
        );
        rejected(
            "EXPLAIN (VERBOSE, ANALYZE) SELECT * FROM users",
            GuardError::ExplainAnalyze,
        );
        // Option names are identifiers — match them case-insensitively.
        rejected("EXPLAIN (analyze) SELECT 1", GuardError::ExplainAnalyze);
        rejected("EXPLAIN (AnAlYzE) SELECT 1", GuardError::ExplainAnalyze);
        // Argument form: still executes when true, and we don't interpret args.
        rejected(
            "EXPLAIN (ANALYZE true) SELECT 1",
            GuardError::ExplainAnalyze,
        );
        rejected(
            "EXPLAIN (ANALYZE) WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            GuardError::ExplainAnalyze,
        );
    }

    #[test]
    fn explain_without_analyze_still_allowed() {
        // The fix must not turn every parenthesised EXPLAIN into a rejection.
        ok("EXPLAIN SELECT 1");
        ok("EXPLAIN (FORMAT JSON) SELECT 1");
        ok("EXPLAIN (VERBOSE) SELECT 1");
        ok("EXPLAIN (COSTS false, FORMAT TEXT) SELECT * FROM users");
    }

    #[test]
    fn writable_cte_rejected() {
        rejected(
            "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            GuardError::WriteInReadPath("INSERT"),
        );
        rejected(
            "WITH x AS (UPDATE t SET a = 1 RETURNING id) SELECT * FROM x",
            GuardError::WriteInReadPath("UPDATE"),
        );
    }

    #[test]
    fn select_into_rejected() {
        rejected("SELECT * INTO new_table FROM t", GuardError::SelectInto);
    }

    #[test]
    fn write_nested_in_body_rejected() {
        // Write buried in a parenthesised subquery used as the outer body,
        // and a write in a CTE nested inside another CTE — both must recurse.
        rejected(
            "(WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x)",
            GuardError::WriteInReadPath("INSERT"),
        );
        rejected(
            "WITH a AS (WITH b AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM b) SELECT * FROM a",
            GuardError::WriteInReadPath("INSERT"),
        );
    }

    #[test]
    fn writes_rejected() {
        rejected_not_allowed("INSERT INTO users (id) VALUES (1)", "INSERT");
        rejected_not_allowed("UPDATE users SET email = 'x'", "UPDATE");
        rejected_not_allowed("DELETE FROM users", "DELETE");
        rejected_not_allowed("TRUNCATE users", "TRUNCATE");
    }

    #[test]
    fn ddl_rejected() {
        rejected_not_allowed("CREATE TABLE t (id int)", "CREATE TABLE");
        rejected_not_allowed("DROP TABLE users", "DROP");
        rejected_not_allowed("ALTER TABLE users ADD COLUMN x int", "ALTER TABLE");
    }

    #[test]
    fn grants_rejected() {
        rejected_not_allowed("GRANT SELECT ON users TO bob", "GRANT");
        rejected_not_allowed("REVOKE SELECT ON users FROM bob", "REVOKE");
    }

    #[test]
    fn transaction_control_rejected() {
        rejected_not_allowed("BEGIN", "BEGIN/START");
        rejected_not_allowed("COMMIT", "COMMIT");
        rejected_not_allowed("ROLLBACK", "ROLLBACK");
    }

    #[test]
    fn locking_select_rejected() {
        rejected("SELECT * FROM users FOR UPDATE", GuardError::Locking);
        rejected("SELECT * FROM users FOR SHARE", GuardError::Locking);
    }

    /// The classic injection trick: comment hides the real statement, then a
    /// second one tries to slip through. AST parsing sees both; we reject on
    /// statement count.
    #[test]
    fn multi_statement_rejected_even_if_first_is_select() {
        let sql = "SELECT 1; DELETE FROM users";
        let got = is_read_only(sql);
        assert!(
            matches!(got, Err(GuardError::MultiStatement(2))),
            "got {got:?}"
        );
    }

    /// `EXPLAIN DELETE FROM users` is still a DELETE-shaped statement —
    /// EXPLAIN without ANALYZE doesn't execute, but we reject anyway for
    /// consistency: the read-only role wouldn't permit it, and an operator
    /// might enable ANALYZE later thinking EXPLAIN is always safe.
    #[test]
    fn explain_of_a_write_rejected() {
        rejected_not_allowed("EXPLAIN DELETE FROM users", "DELETE");
        rejected_not_allowed("EXPLAIN (FORMAT JSON) UPDATE users SET x = 1", "UPDATE");
    }

    #[test]
    fn copy_rejected() {
        // COPY FROM is a write; COPY TO STDOUT is read but we're conservative.
        rejected_not_allowed("COPY users FROM '/tmp/foo'", "COPY");
        rejected_not_allowed("COPY users TO STDOUT", "COPY");
    }

    #[test]
    fn unparseable_rejected_as_parse_error() {
        assert!(matches!(is_read_only("SELEKT 1"), Err(GuardError::Parse)));
        assert!(matches!(is_read_only(""), Err(GuardError::Parse)));
        assert!(matches!(is_read_only("   "), Err(GuardError::Parse)));
    }

    // --- Function denylist ---

    fn rejected_denied(sql: &str, fn_name: &str) {
        match is_read_only(sql) {
            Err(GuardError::DeniedFunction(got)) => {
                assert_eq!(got, fn_name, "wrong denied function for `{sql}`");
            }
            other => panic!("expected DeniedFunction({fn_name}) for `{sql}`, got {other:?}"),
        }
    }

    #[test]
    fn pg_read_file_in_projection_rejected() {
        rejected_denied("SELECT pg_read_file('/etc/passwd')", "pg_read_file");
    }

    #[test]
    fn pg_read_binary_file_rejected() {
        rejected_denied(
            "SELECT pg_read_binary_file('/etc/shadow')",
            "pg_read_binary_file",
        );
    }

    #[test]
    fn pg_ls_dir_rejected() {
        rejected_denied("SELECT * FROM pg_ls_dir('/tmp')", "pg_ls_dir");
        // `LATERAL` puts the same call in a different table-factor variant.
        rejected_denied("SELECT * FROM t, LATERAL pg_ls_dir('/tmp')", "pg_ls_dir");
    }

    #[test]
    fn pg_stat_file_rejected() {
        rejected_denied("SELECT pg_stat_file('/etc/passwd')", "pg_stat_file");
    }

    #[test]
    fn lo_export_rejected() {
        rejected_denied("SELECT lo_export(1234, '/tmp/out')", "lo_export");
    }

    #[test]
    fn lo_import_rejected() {
        rejected_denied("SELECT lo_import('/etc/passwd')", "lo_import");
    }

    #[test]
    fn denied_function_in_where_clause_rejected() {
        rejected_denied(
            "SELECT id FROM t WHERE pg_read_file('/etc/passwd') IS NOT NULL",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_function_in_subquery_rejected() {
        rejected_denied(
            "SELECT id FROM t WHERE id IN (SELECT length(pg_read_file('/etc/passwd')))",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_function_in_cte_rejected() {
        rejected_denied(
            "WITH x AS (SELECT pg_read_file('/etc/passwd') AS data) SELECT data FROM x",
            "pg_read_file",
        );
    }

    #[test]
    fn schema_qualified_denied_function_rejected() {
        // Attackers may try to qualify the name to confuse a naive denylist.
        rejected_denied(
            "SELECT pg_catalog.pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_function_case_insensitive() {
        // SQL identifiers are case-insensitive; the guard must be too.
        rejected_denied("SELECT PG_READ_FILE('/etc/passwd')", "pg_read_file");
    }

    #[test]
    fn denied_function_in_having_rejected() {
        rejected_denied(
            "SELECT id FROM t GROUP BY id HAVING pg_read_file('/etc/passwd') IS NOT NULL",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_function_in_query_tail_rejected() {
        // ORDER BY / LIMIT / OFFSET hang off `Query`, not off the SELECT body —
        // the Visit derive reaches them via the same walk as the projection.
        rejected_denied(
            "SELECT id FROM t ORDER BY pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT id FROM t LIMIT length(pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT id FROM t OFFSET length(pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
        // Same tail on an inner query, reached through the CTE walk.
        rejected_denied(
            "WITH x AS (SELECT id FROM t ORDER BY pg_read_file('/etc/passwd')) SELECT * FROM x",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_function_in_join_constraint_rejected() {
        // A join's ON predicate is an expression position like any other.
        rejected_denied(
            "SELECT a.id FROM a JOIN b ON pg_read_file('/etc/passwd') IS NOT NULL",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT a.id FROM a LEFT JOIN b ON a.id = length(pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
        // Parenthesised join tree — a `NestedJoin` table factor.
        rejected_denied(
            "SELECT * FROM (a JOIN b ON pg_read_file('/etc/passwd') IS NOT NULL)",
            "pg_read_file",
        );
    }

    #[test]
    fn safe_functions_allowed() {
        // Ensure the denylist doesn't block ordinary aggregate/window functions.
        ok("SELECT now()");
        ok("SELECT count(*) FROM users");
        ok("SELECT sum(amount) FROM orders GROUP BY user_id");
        ok("SELECT lower(email) FROM users");
        ok("SELECT coalesce(name, 'unknown') FROM t");
    }

    // --- Escape-position regressions (issue #138) ---
    //
    // Each of these was empirically shown to reach the target DB with the old
    // hand-rolled `check_expr` — its `_ => Ok(())` fallthrough silently allowed
    // every `Expr` variant the author hadn't listed. The visitor-based walk
    // covers them without enumeration; these tests pin that guarantee.

    #[test]
    fn denied_in_exists_subquery_rejected() {
        rejected_denied(
            "SELECT 1 WHERE EXISTS (SELECT pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_any_all_subquery_rejected() {
        rejected_denied(
            "SELECT a FROM t WHERE a = ANY(SELECT pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT a FROM t WHERE a = ALL(SELECT pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_tuple_rejected() {
        rejected_denied("SELECT (pg_read_file('/etc/passwd'), 1)", "pg_read_file");
    }

    #[test]
    fn denied_in_array_literal_rejected() {
        rejected_denied("SELECT ARRAY[pg_read_file('/etc/passwd')]", "pg_read_file");
    }

    #[test]
    fn denied_in_filter_clause_rejected() {
        rejected_denied(
            "SELECT count(*) FILTER (WHERE pg_read_file('/etc/passwd') IS NOT NULL) FROM t",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_window_frame_rejected() {
        rejected_denied(
            "SELECT sum(a) OVER (ORDER BY pg_read_file('/etc/passwd')) FROM t",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_distinct_on_rejected() {
        rejected_denied(
            "SELECT DISTINCT ON (pg_read_file('/etc/passwd')) a FROM t",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_unnest_rejected() {
        rejected_denied(
            "SELECT * FROM UNNEST(ARRAY[pg_read_file('/etc/passwd')])",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_is_distinct_from_rejected() {
        rejected_denied(
            "SELECT a FROM t WHERE a IS DISTINCT FROM pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT a FROM t WHERE a IS NOT DISTINCT FROM pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_substring_rejected() {
        // `substring(<expr> FROM ... FOR ...)` is `Expr::Substring`, not a
        // `Function` call — and the old walker fell through it.
        rejected_denied(
            "SELECT substring(pg_read_file('/etc/passwd') FROM 1 FOR 2)",
            "pg_read_file",
        );
    }

    #[test]
    fn denied_in_grouping_sets_rejected() {
        rejected_denied(
            "SELECT a FROM t GROUP BY GROUPING SETS ((pg_read_file('/etc/passwd')))",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT a FROM t GROUP BY ROLLUP (pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
        rejected_denied(
            "SELECT a FROM t GROUP BY CUBE (pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
    }

    // --- Write mode (Access::ReadWrite) -------------------------------------

    fn ok_write(sql: &str) {
        let got = check_sql(sql, Access::ReadWrite);
        assert!(
            got.is_ok(),
            "expected `{sql}` allowed for writes, got {got:?}"
        );
    }

    fn rejected_write_not_allowed(sql: &str, kind: &str) {
        match check_sql(sql, Access::ReadWrite) {
            Err(GuardError::NotAllowed(got)) => assert_eq!(got, kind, "for `{sql}`"),
            other => panic!("expected NotAllowed({kind}) for `{sql}`, got {other:?}"),
        }
    }

    fn rejected_write(sql: &str, want: GuardError) {
        let got = check_sql(sql, Access::ReadWrite);
        assert_eq!(
            got,
            Err(want.clone()),
            "expected `{sql}` rejected as {want:?}, got {got:?}"
        );
    }

    fn rejected_write_denied(sql: &str, fn_name: &str) {
        match check_sql(sql, Access::ReadWrite) {
            Err(GuardError::DeniedFunction(got)) => assert_eq!(got, fn_name, "for `{sql}`"),
            other => panic!("expected DeniedFunction({fn_name}) for `{sql}`, got {other:?}"),
        }
    }

    #[test]
    fn write_mode_allows_data_writes() {
        ok_write("INSERT INTO users (id, email) VALUES (1, 'a@b.c')");
        ok_write("INSERT INTO archive SELECT * FROM users WHERE active = false");
        ok_write("UPDATE users SET email = 'x@y.z' WHERE id = 1");
        ok_write("DELETE FROM users WHERE id = 1");
        ok_write("INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET id = 2");
        ok_write("INSERT INTO t (id) VALUES (1) ON CONFLICT DO NOTHING");
        ok_write("DELETE FROM users WHERE id = 1 RETURNING id, email");
    }

    #[test]
    fn write_mode_still_allows_reads() {
        // Read is a subset of read-write — a `query_write` caller can still SELECT.
        ok_write("SELECT id, email FROM users WHERE id = 1");
        ok_write("WITH x AS (SELECT 1) SELECT * FROM x");
        ok_write("EXPLAIN SELECT 1");
    }

    #[test]
    fn write_mode_still_blocks_schema_mods() {
        // "write data, no schema mods" — DDL and privilege ops stay blocked
        // even with a write grant.
        rejected_write_not_allowed("TRUNCATE users", "TRUNCATE");
        rejected_write_not_allowed("DROP TABLE users", "DROP");
        rejected_write_not_allowed("CREATE TABLE t (id int)", "CREATE TABLE");
        rejected_write_not_allowed("ALTER TABLE users ADD COLUMN x int", "ALTER TABLE");
        rejected_write_not_allowed("GRANT SELECT ON users TO bob", "GRANT");
        rejected_write_not_allowed("REVOKE SELECT ON users FROM bob", "REVOKE");
        rejected_write_not_allowed("COPY users FROM '/tmp/foo'", "COPY");
        rejected_write_not_allowed("BEGIN", "BEGIN/START");
    }

    #[test]
    fn write_mode_still_rejects_multi_statement() {
        // A write can't ride in behind another statement.
        assert!(matches!(
            check_sql("DELETE FROM users; DROP TABLE users", Access::ReadWrite),
            Err(GuardError::MultiStatement(2))
        ));
        assert!(matches!(
            check_sql(
                "INSERT INTO t VALUES (1); INSERT INTO t VALUES (2)",
                Access::ReadWrite
            ),
            Err(GuardError::MultiStatement(2))
        ));
    }

    #[test]
    fn write_mode_still_blocks_denied_functions() {
        // Filesystem/network functions stay denied in every read position of a
        // write statement.
        rejected_write_denied(
            "INSERT INTO t (data) VALUES (pg_read_file('/etc/passwd'))",
            "pg_read_file",
        );
        rejected_write_denied(
            "INSERT INTO t SELECT pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
        rejected_write_denied(
            "UPDATE t SET data = pg_read_file('/etc/passwd') WHERE id = 1",
            "pg_read_file",
        );
        rejected_write_denied(
            "DELETE FROM t WHERE data = pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
        rejected_write_denied(
            "DELETE FROM t WHERE id = 1 RETURNING pg_read_file('/etc/passwd')",
            "pg_read_file",
        );
        rejected_write_denied(
            "INSERT INTO t (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET data = pg_read_file('/x')",
            "pg_read_file",
        );
    }

    #[test]
    fn write_mode_rejects_write_hidden_in_select_body() {
        // Write mode widens to a *top-level* INSERT/UPDATE/DELETE only. A write
        // buried in a SELECT's CTE stays rejected — the top-level statement is a
        // Query, which is always walked read-only. Use a plain write instead.
        rejected_write(
            "WITH x AS (INSERT INTO t VALUES (1) RETURNING id) SELECT * FROM x",
            GuardError::WriteInReadPath("INSERT"),
        );
        rejected_write(
            "WITH x AS (UPDATE t SET a = 1 RETURNING id) SELECT * FROM x",
            GuardError::WriteInReadPath("UPDATE"),
        );
    }

    #[test]
    fn read_mode_rejects_writes_write_mode_gates_them() {
        // The same INSERT: rejected under ReadOnly, allowed under ReadWrite.
        assert!(matches!(
            check_sql("INSERT INTO t VALUES (1)", Access::ReadOnly),
            Err(GuardError::NotAllowed("INSERT"))
        ));
        assert!(check_sql("INSERT INTO t VALUES (1)", Access::ReadWrite).is_ok());
    }
}

#[cfg(test)]
mod proptests {
    //! Random hammer: the guard must never panic, never allow a write-shaped
    //! statement, and never crash on garbage input. Doesn't try to be a
    //! complete grammar — just throws shapes at it.

    use super::*;
    use proptest::prelude::*;

    fn arbitrary_safe_select() -> impl Strategy<Value = String> {
        proptest::sample::select(&[
            "SELECT 1",
            "SELECT id FROM t",
            "SELECT * FROM users WHERE id = 1",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "EXPLAIN SELECT 1",
            "EXPLAIN (FORMAT JSON) SELECT now()",
        ])
        .prop_map(|s| s.to_string())
    }

    fn arbitrary_write_or_ddl() -> impl Strategy<Value = String> {
        proptest::sample::select(&[
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1",
            "DELETE FROM t",
            "TRUNCATE t",
            "DROP TABLE t",
            "ALTER TABLE t ADD COLUMN y int",
            "CREATE TABLE t (id int)",
            "GRANT SELECT ON t TO bob",
            "REVOKE SELECT ON t FROM bob",
        ])
        .prop_map(|s| s.to_string())
    }

    fn arbitrary_denied_function() -> impl Strategy<Value = String> {
        proptest::sample::select(&[
            "SELECT pg_read_file('/etc/passwd')",
            "SELECT pg_read_binary_file('/etc/shadow')",
            "SELECT pg_ls_dir('/tmp')",
            "SELECT pg_stat_file('/etc/passwd')",
            "SELECT lo_export(1, '/tmp/x')",
            "SELECT lo_import('/etc/passwd')",
        ])
        .prop_map(|s| s.to_string())
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_strings(s in ".{0,200}") {
            // We don't care about the result — just that the parser path
            // never aborts. RecursionLimitExceeded is fine; it's a typed
            // GuardError::Parse, not a panic.
            let _ = is_read_only(&s);
        }

        #[test]
        fn safe_selects_always_allowed(sql in arbitrary_safe_select()) {
            prop_assert!(is_read_only(&sql).is_ok(), "rejected: {sql}");
        }

        #[test]
        fn writes_always_rejected(sql in arbitrary_write_or_ddl()) {
            prop_assert!(
                matches!(is_read_only(&sql), Err(GuardError::NotAllowed(_))),
                "wrongly allowed: {sql}"
            );
        }

        /// Combining safe + unsafe via `;` always rejects on MultiStatement
        /// regardless of order — never short-circuits to "first one was OK".
        #[test]
        fn safe_then_unsafe_rejected(safe in arbitrary_safe_select(), unsafe_ in arbitrary_write_or_ddl()) {
            let combined = format!("{safe}; {unsafe_}");
            let got = is_read_only(&combined);
            prop_assert!(
                matches!(got, Err(GuardError::MultiStatement(_)) | Err(GuardError::NotAllowed(_)) | Err(GuardError::Parse)),
                "wrongly handled: `{combined}` → {got:?}"
            );
        }

        #[test]
        fn denied_functions_always_rejected(sql in arbitrary_denied_function()) {
            prop_assert!(
                matches!(is_read_only(&sql), Err(GuardError::DeniedFunction(_))),
                "wrongly allowed: {sql}"
            );
        }
    }
}
