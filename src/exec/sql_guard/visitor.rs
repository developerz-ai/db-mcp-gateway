//! Substructure walk: denied functions, nested writes, locking clauses and
//! `SELECT ... INTO`, driven by sqlparser's `Visit` derive.

use sqlparser::ast::{
    AccessExpr, Expr, FunctionArg, FunctionArgExpr, Ident, ObjectName, Query, SelectItem, SetExpr,
    Statement, TableFactor, Visitor,
};
use std::ops::ControlFlow;

use super::GuardError;
use super::calls::Calls;
use super::denylist::{denied_function, denied_schema, denied_whole_row_call};

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
///
/// Also: a relation in a denied schema (`cron.job`), and an `UPDATE` of
/// `pg_settings`, whose rule calls `set_config`.
/// 4. Nested `Statement` — sqlparser encodes a writable CTE as a Query whose
///    body is `SetExpr::Insert(Statement)`, so any `pre_visit_statement`
///    firing *after* the top level is a write hiding in a read path.
///
/// Because every expression, query, and table-factor position is walked by
/// the derive, this needs no per-variant enumeration and cannot silently miss
/// a node type a future sqlparser bump adds.
pub(super) struct GuardVisitor {
    top_seen: bool,
    calls: Calls,
}

impl GuardVisitor {
    pub(super) fn new() -> Self {
        Self {
            top_seen: false,
            calls: Calls::default(),
        }
    }

    /// The functions the statement calls, for the second parser to agree with.
    pub(super) fn into_calls(self) -> Calls {
        self.calls
    }
}

impl Visitor for GuardVisitor {
    type Break = GuardError;

    fn pre_visit_statement(&mut self, stmt: &Statement) -> ControlFlow<GuardError> {
        if !self.top_seen {
            self.top_seen = true;
            return break_on(check_write_target(stmt));
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
        break_on(check_table_commands(q.body.as_ref()))
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<GuardError> {
        self.calls.record_expr(expr);
        break_on(match expr {
            Expr::Function(f) => check_denied_name(&f.name),
            Expr::CompoundIdentifier(parts) => check_compound_identifier(parts),
            Expr::CompoundFieldAccess { access_chain, .. } => {
                access_chain.iter().try_for_each(check_access)
            }
            _ => Ok(()),
        })
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<GuardError> {
        break_on(match schema_label(relation) {
            Some(label) => Err(GuardError::DeniedRelation(label)),
            None => Ok(()),
        })
    }

    fn pre_visit_table_factor(&mut self, tf: &TableFactor) -> ControlFlow<GuardError> {
        self.calls.record_table_factor(tf);
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
        SetExpr::Select(s) => s.into.is_some() || s.projection.iter().any(is_bare_into),
        SetExpr::SetOperation { left, right, .. } => {
            body_has_select_into(left) || body_has_select_into(right)
        }
        _ => false,
    }
}

/// `TABLE s.t`, a query body that is a relation's name. Recurses as above.
fn check_table_commands(body: &SetExpr) -> Result<(), GuardError> {
    match body {
        SetExpr::Table(table) => {
            let schema = table.schema_name.as_ref();
            match schema.and_then(|schema| denied_schema(&schema.value)) {
                Some(label) => Err(GuardError::DeniedRelation(label)),
                None => Ok(()),
            }
        }
        SetExpr::SetOperation { left, right, .. } => {
            check_table_commands(left)?;
            check_table_commands(right)
        }
        _ => Ok(()),
    }
}

/// `SELECT INTO t FROM x` — an empty target list — reaches sqlparser as a
/// column named `INTO` aliased `t`. Unquoted, `INTO` is reserved in
/// Postgres, so no real column is spelled that way.
fn is_bare_into(item: &SelectItem) -> bool {
    let ident = match item {
        SelectItem::UnnamedExpr(Expr::Identifier(ident))
        | SelectItem::ExprWithAlias {
            expr: Expr::Identifier(ident),
            ..
        } => ident,
        _ => return false,
    };
    ident.quote_style.is_none() && ident.value.eq_ignore_ascii_case("into")
}

/// The top-level statement's write target. `pg_settings` has an `UPDATE`
/// rule that calls `set_config`, a session change that would outlive the
/// statement on a pooled connection.
fn check_write_target(stmt: &Statement) -> Result<(), GuardError> {
    let Statement::Update(update) = stmt else {
        return Ok(());
    };
    let TableFactor::Table {
        name, alias, args, ..
    } = &update.table.relation
    else {
        return Ok(());
    };
    let relation = name.0.last().and_then(|part| part.as_ident());
    // sqlparser reads `UPDATE ONLY t` as table `ONLY` aliased `t`, and
    // `UPDATE ONLY (t)` as a call of `ONLY`: only then is the relation in
    // the alias or the arguments. Otherwise the alias is just a name.
    let misparsed_only = name.0.len() == 1
        && relation.is_some_and(|ident| {
            ident.quote_style.is_none() && ident.value.eq_ignore_ascii_case("only")
        });
    let arg_names = args
        .iter()
        .flat_map(|a| &a.args)
        .filter_map(|arg| match arg {
            FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(ident))) => Some(ident),
            FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::CompoundIdentifier(parts))) => {
                parts.last()
            }
            _ => None,
        });
    let names: Vec<&Ident> = if misparsed_only {
        alias.iter().map(|a| &a.name).chain(arg_names).collect()
    } else {
        relation.into_iter().collect()
    };
    if names
        .iter()
        .any(|ident| ident.value.eq_ignore_ascii_case("pg_settings"))
    {
        return Err(GuardError::DeniedFunction("set_config"));
    }
    Ok(())
}

/// `alias.name` passes the alias's whole row to `name`; with more parts,
/// `t.col.name` passes a column's value — any one-argument call.
fn check_compound_identifier(parts: &[Ident]) -> Result<(), GuardError> {
    let Some(last) = parts.last() else {
        return Ok(());
    };
    let denied = match parts.len() {
        2 => denied_whole_row_call(&last.value),
        _ => denied_function(&last.value),
    };
    match denied {
        Some(denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
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
    if let Some(label) = schema_label(name) {
        return Err(GuardError::DeniedFunction(label));
    }
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

/// The label of a denied schema among `name`'s qualifiers.
fn schema_label(name: &ObjectName) -> Option<&'static str> {
    let qualifiers = name.0.split_last().map_or(&[][..], |(_, q)| q);
    qualifiers
        .iter()
        .filter_map(|part| part.as_ident())
        .find_map(|ident| denied_schema(&ident.value))
}
