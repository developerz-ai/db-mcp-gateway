//! The functions sqlparser's tree calls, named as Postgres's tree names
//! them, for the second parser (`pg_query_check`) to agree with.

use std::collections::BTreeSet;

use sqlparser::ast::{Expr, Ident, ObjectName, TableFactor};

/// Called names, folded as Postgres folds identifiers.
#[derive(Debug, Default)]
pub(super) struct Calls(BTreeSet<String>);

impl Calls {
    pub(super) fn names(&self) -> &BTreeSet<String> {
        &self.0
    }

    #[cfg(test)]
    pub(super) fn of(names: &[&str]) -> Self {
        Self(names.iter().map(|name| (*name).to_owned()).collect())
    }

    /// A call in expression position. sqlparser models a few calls as their
    /// own expressions, which Postgres's grammar turns into plain calls of
    /// the named functions.
    pub(super) fn record_expr(&mut self, expr: &Expr) {
        let implied: &[&str] = match expr {
            Expr::Function(f) => return self.record_name(&f.name),
            Expr::Ceil { .. } => &["ceil", "ceiling"],
            Expr::Floor { .. } => &["floor"],
            Expr::Substring { .. } => &["substring", "substr"],
            Expr::SimilarTo { .. } => &["similar_to_escape"],
            Expr::Like {
                escape_char: Some(_),
                ..
            }
            | Expr::ILike {
                escape_char: Some(_),
                ..
            } => &["like_escape"],
            _ => &[],
        };
        self.0.extend(implied.iter().map(|name| (*name).to_owned()));
    }

    /// A call as a table source: `FROM f(…)`, `FROM unnest(…)`.
    pub(super) fn record_table_factor(&mut self, tf: &TableFactor) {
        match tf {
            TableFactor::Table {
                name,
                args: Some(_),
                ..
            }
            | TableFactor::Function { name, .. } => self.record_name(name),
            TableFactor::UNNEST { .. } => {
                self.0.insert("unnest".to_owned());
            }
            _ => {}
        }
    }

    fn record_name(&mut self, name: &ObjectName) {
        if let Some(ident) = name.0.last().and_then(|part| part.as_ident()) {
            self.0.insert(folded(ident));
        }
    }
}

/// An identifier as Postgres stores it: unquoted ASCII letters fold to
/// lower case, a quoted name is kept as written.
fn folded(ident: &Ident) -> String {
    match ident.quote_style {
        None => ident.value.to_ascii_lowercase(),
        Some(_) => ident.value.clone(),
    }
}
