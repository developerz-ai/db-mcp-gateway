//! Substructure walk: denied functions, nested writes, locking clauses and
//! `SELECT ... INTO`, driven by sqlparser's `Visit` derive.

use sqlparser::ast::{Expr, ObjectName, Query, SetExpr, Statement, TableFactor, Visitor};
use std::ops::ControlFlow;

use super::GuardError;

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
pub(super) struct GuardVisitor {
    top_seen: bool,
}

impl GuardVisitor {
    pub(super) fn new() -> Self {
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
        if let Expr::Function(f) = expr
            && let Err(err) = check_denied_name(&f.name)
        {
            return ControlFlow::Break(err);
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
    // A non-identifier name part (a dialect's `IDENTIFIER(...)`-style computed
    // name) cannot be matched against the denylist, so it is refused outright.
    let fn_name = match name.0.last() {
        None => "",
        Some(part) => match part.as_ident() {
            Some(ident) => ident.value.as_str(),
            None => return Err(GuardError::NotAllowed("computed function name")),
        },
    };
    match DENIED_FUNCTIONS
        .iter()
        .find(|&&d| d.eq_ignore_ascii_case(fn_name))
    {
        Some(&denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
    }
}
