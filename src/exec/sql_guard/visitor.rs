//! Substructure walk: denied functions, nested writes, locking clauses and
//! `SELECT ... INTO`, driven by sqlparser's `Visit` derive.

use sqlparser::ast::{
    AccessExpr, Expr, Ident, ObjectName, Query, SetExpr, Statement, TableFactor, Visitor,
};
use std::ops::ControlFlow;

use super::GuardError;
use super::denylist::denied_function;

/// Substructure guard, run once the top-level [`check_statement_shape`] has
/// admitted the statement. Enforces four things via sqlparser's `Visit`
/// derive, which walks every child node automatically:
///
/// 1. Denied-function calls: `Expr::Function`, `TableFactor::{Table,
///    Function}` when a set-returning denied function is used as a table
///    source, and attribute notation — Postgres resolves `(x).f` and
///    `row.f` to `f(x)` / `f(row)` when no such column exists.
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
        break_on(match expr {
            Expr::Function(f) => check_denied_name(&f.name),
            Expr::CompoundIdentifier(parts) => parts.last().map_or(Ok(()), check_attribute),
            Expr::CompoundFieldAccess { access_chain, .. } => {
                access_chain.iter().try_for_each(check_access)
            }
            _ => Ok(()),
        })
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<GuardError> {
        // `FROM pg_ls_dir(...)` and `FROM LATERAL pg_ls_dir(...)` place the
        // denied name on a TableFactor, not an Expr::Function — check both
        // shapes here so it is caught symmetrically with the expression pass.
        // A `Table` without arguments is a relation, not a call: a table
        // named `lo_items` must not trip the `lo_*` family.
        let name = match tf {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            }
            | TableFactor::Function { name, .. } => name,
            _ => return ControlFlow::Continue(()),
        };
        break_on(check_denied_name(name))
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

/// One step of an access chain: `.name` may be a call in attribute notation.
/// A dot followed by anything but a name is nothing Postgres parses.
fn check_access(access: &AccessExpr) -> Result<(), GuardError> {
    match access {
        AccessExpr::Dot(Expr::Identifier(ident)) => check_attribute(ident),
        AccessExpr::Dot(Expr::Function(_)) | AccessExpr::Subscript(_) => Ok(()),
        AccessExpr::Dot(_) => Err(GuardError::NotAllowed("computed field access")),
    }
}

/// A name in attribute position (`x.name`): a column, or a call of `name`.
fn check_attribute(ident: &Ident) -> Result<(), GuardError> {
    match denied_function(&ident.value) {
        Some(denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
    }
}

fn break_on(result: Result<(), GuardError>) -> ControlFlow<GuardError> {
    match result {
        Ok(()) => ControlFlow::Continue(()),
        Err(e) => ControlFlow::Break(e),
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
    match denied_function(fn_name) {
        Some(denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
    }
}
