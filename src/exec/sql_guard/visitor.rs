//! Substructure walk: denied functions, nested writes, locking clauses and
//! `SELECT ... INTO`, driven by sqlparser's `Visit` derive.

use sqlparser::ast::{Expr, ObjectName, Query, SetExpr, Statement, TableFactor, Visitor};
use std::ops::ControlFlow;

use super::GuardError;

/// Functions the gateway always blocks, regardless of the Postgres role's
/// privileges. Matched case-insensitively on the last name component, so a
/// schema-qualified call (`pg_catalog.pg_read_file`) is caught too.
///
/// This is layer three. The DB role is layer one and the read-only
/// transaction layer two; the list exists for the functions those two do
/// not stop — ones a read-only transaction still runs, or that run SQL the
/// guard never sees:
///
/// - filesystem: `pg_read_file`, `pg_read_binary_file`, `pg_stat_file`,
///   `pg_ls_*` (every directory listing), `pg_current_logfile`, and the
///   large-object family `lo_*` / `lowrite` (`lo_export` writes a server
///   file; `lo_from_bytea` creates an object — no side effect is allowed
///   from a read).
/// - session state: `set_config` (a session-level change would outlive the
///   query on a pooled connection) and every advisory lock function (a
///   session lock blocks other users until the connection is reset).
/// - other backends: `pg_cancel_backend`, `pg_terminate_backend`.
/// - dynamic SQL: `query_to_xml*`, `cursor_to_xml*`, `table_to_xml*`,
///   `schema_to_xml*`, `database_to_xml*`, `ts_stat` and `ts_rewrite` execute
///   SQL text or whole-schema reads the guard cannot inspect — a denied call
///   inside that text runs unseen; `dblink*` reaches other servers.
/// - messages to other sessions: `pg_notify` and `pg_logical_emit_message`
///   run in a read-only transaction and, on its commit, reach every
///   `LISTEN`er or logical-decoding consumer (job queues, CDC pipelines).
const DENIED_FUNCTIONS: &[Denied] = &[
    Denied::Exact("pg_read_file"),
    Denied::Exact("pg_read_binary_file"),
    Denied::Exact("pg_stat_file"),
    Denied::Exact("pg_current_logfile"),
    Denied::Exact("pg_ls_dir"),
    Denied::Prefix("pg_ls_", "pg_ls_*"),
    Denied::Exact("lo_export"),
    Denied::Exact("lo_import"),
    Denied::Prefix("lo_", "lo_*"),
    Denied::Exact("lowrite"),
    Denied::Exact("set_config"),
    Denied::Prefix("pg_advisory_", "pg_advisory_*"),
    Denied::Prefix("pg_try_advisory_", "pg_try_advisory_*"),
    Denied::Exact("pg_cancel_backend"),
    Denied::Exact("pg_terminate_backend"),
    Denied::Prefix("query_to_xml", "query_to_xml*"),
    Denied::Prefix("cursor_to_xml", "cursor_to_xml*"),
    Denied::Prefix("table_to_xml", "table_to_xml*"),
    Denied::Prefix("schema_to_xml", "schema_to_xml*"),
    Denied::Prefix("database_to_xml", "database_to_xml*"),
    Denied::Prefix("dblink", "dblink*"),
    Denied::Exact("pg_notify"),
    Denied::Exact("pg_logical_emit_message"),
    Denied::Exact("ts_stat"),
    Denied::Exact("ts_rewrite"),
];

/// One denylist entry. Exact names come first in [`DENIED_FUNCTIONS`] so a
/// well-known name is reported as itself rather than as its family.
#[derive(Debug, Clone, Copy)]
enum Denied {
    Exact(&'static str),
    /// `(prefix, label)` — the label is what the error reports.
    Prefix(&'static str, &'static str),
}

impl Denied {
    /// The name to report if `fn_name` matches this entry.
    fn matches(self, fn_name: &str) -> Option<&'static str> {
        match self {
            Self::Exact(name) => name.eq_ignore_ascii_case(fn_name).then_some(name),
            Self::Prefix(prefix, label) => fn_name
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                .then_some(label),
        }
    }
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
    match DENIED_FUNCTIONS.iter().find_map(|d| d.matches(fn_name)) {
        Some(denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
    }
}
