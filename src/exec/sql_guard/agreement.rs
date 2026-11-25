//! The second parser: libpg_query — Postgres's own grammar — must read the
//! statement the way sqlparser did. The guard decides on sqlparser's tree;
//! the target runs Postgres's. `lexical` refuses text the two split into
//! different tokens; this refuses text they build into different statements:
//! the count, the kind, and every function Postgres would call must match.
//! The denylists are held against Postgres's tree too, so a name only it
//! sees is refused by name.

use pg_query::protobuf::CoercionForm;
use sqlparser::ast::Statement;

use super::GuardError;
use super::calls::Calls;
use super::denylist::{denied_function, denied_relation, denied_schema, denied_whole_row_call};
use super::pg_tree::schema::{NodeType, number};
use super::pg_tree::wire::{Message, walk};
use super::pg_tree::{self, Unreadable};

/// The kind of statement the guard admits, as either parser reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Select,
    Insert,
    Update,
    Delete,
}

impl Kind {
    /// sqlparser's reading of an admitted statement (EXPLAIN unwrapped).
    pub(super) fn of(stmt: &Statement) -> Option<Self> {
        Some(match stmt {
            Statement::Query(_) => Self::Select,
            Statement::Insert(_) => Self::Insert,
            Statement::Update(_) => Self::Update,
            Statement::Delete(_) => Self::Delete,
            _ => return None,
        })
    }

    fn of_node(of: NodeType) -> Option<Self> {
        Some(match of {
            NodeType::SelectStmt => Self::Select,
            NodeType::InsertStmt => Self::Insert,
            NodeType::UpdateStmt => Self::Update,
            NodeType::DeleteStmt => Self::Delete,
            _ => return None,
        })
    }
}

/// What sqlparser made of the statement the guard admitted.
#[derive(Debug)]
pub(super) struct Reading {
    pub(super) explained: bool,
    pub(super) kind: Kind,
    pub(super) calls: Calls,
}

const SYNTAX: GuardError = GuardError::ParserDisagreement("syntax");
const COUNT: GuardError = GuardError::ParserDisagreement("statement count");
const KIND: GuardError = GuardError::ParserDisagreement("statement kind");
const CALLS: GuardError = GuardError::ParserDisagreement("function calls");

impl From<Unreadable> for GuardError {
    fn from(why: Unreadable) -> Self {
        match why {
            Unreadable::TooDeep => Self::TooDeep,
            Unreadable::Node => KIND,
            Unreadable::Syntax | Unreadable::Malformed => SYNTAX,
        }
    }
}

/// Refuse `sql` unless libpg_query reads it as `reading` says. Runs on a
/// parser thread ([`pg_tree::parse`] says why).
pub(super) fn check_agreement(sql: &str, reading: &Reading) -> Result<(), GuardError> {
    let tree = pg_tree::parse(sql)?;
    let statements = tree.statements()?;
    let [raw] = statements.as_slice() else {
        return Err(COUNT);
    };
    let (explained, stmt) = unwrap_explain(only_node(*raw, number::RAWSTMT_STMT)?)?;
    if explained != reading.explained || Kind::of_node(stmt.of) != Some(reading.kind) {
        return Err(KIND);
    }

    let mut found = Found::default();
    walk(stmt, |message| found.record(message))?;
    let writes = usize::from(reading.kind != Kind::Select);
    if found.writes != writes {
        return Err(KIND);
    }
    let seen = reading.calls.names();
    if found.calls.iter().any(|call| !seen.contains(*call)) {
        return Err(CALLS);
    }
    Ok(())
}

/// The one node of field `number`.
fn only_node(message: Message<'_>, number: u32) -> Result<Message<'_>, Unreadable> {
    match *message.nodes(number)?.as_slice() {
        [node] => Ok(node),
        _ => Err(Unreadable::Malformed),
    }
}

/// The statement under an `EXPLAIN`, and whether there was one. An
/// `ANALYZE` option executes the statement, whichever parser saw it.
fn unwrap_explain(stmt: Message<'_>) -> Result<(bool, Message<'_>), GuardError> {
    if stmt.of != NodeType::ExplainStmt {
        return Ok((false, stmt));
    }
    for option in stmt.nodes(number::EXPLAINSTMT_OPTIONS)? {
        if option.of != NodeType::DefElem {
            return Err(SYNTAX);
        }
        // Postgres's grammar writes `ANALYSE` so too.
        if option.text(number::DEFELEM_DEFNAME)? == "analyze" {
            return Err(GuardError::ExplainAnalyze);
        }
    }
    Ok((true, only_node(stmt, number::EXPLAINSTMT_QUERY)?))
}

/// What Postgres's tree holds that sqlparser's must agree with.
#[derive(Debug, Default)]
struct Found<'a> {
    /// Data-modifying statements, the top-level one included.
    writes: usize,
    /// Names called as `f(…)`. SQL-syntax forms (`EXTRACT(… FROM …)`,
    /// `x AT TIME ZONE z`) are sqlparser expressions, not calls, and are
    /// held only against the denylist.
    calls: Vec<&'a str>,
}

impl<'a> Found<'a> {
    fn record(&mut self, message: Message<'a>) -> Result<(), GuardError> {
        match message.of {
            NodeType::FuncCall => self.record_call(message),
            NodeType::RangeVar => check_relation(message),
            NodeType::ColumnRef => check_column(message),
            NodeType::AIndirection => check_attributes(message),
            NodeType::UpdateStmt => {
                self.writes += 1;
                check_update_target(message)
            }
            NodeType::InsertStmt | NodeType::DeleteStmt | NodeType::MergeStmt => {
                self.writes += 1;
                Ok(())
            }
            // The first parser refuses these, under their own errors.
            NodeType::LockingClause | NodeType::IntoClause | NodeType::ExplainStmt => Err(KIND),
            _ => Ok(()),
        }
    }

    fn record_call(&mut self, call: Message<'a>) -> Result<(), GuardError> {
        let parts = names(call.nodes(number::FUNCCALL_FUNCNAME)?)?;
        let Some((name, qualifiers)) = parts.split_last() else {
            return Err(CALLS);
        };
        if let Some(label) = qualifiers.iter().find_map(|q| denied_schema(q)) {
            return Err(GuardError::DeniedFunction(label));
        }
        refuse_function(denied_function(name))?;
        if call.number(number::FUNCCALL_FUNCFORMAT)? != CoercionForm::CoerceSqlSyntax as u64 {
            self.calls.push(name);
        }
        Ok(())
    }
}

/// A list of `String` nodes.
fn names<'a>(parts: Vec<Message<'a>>) -> Result<Vec<&'a str>, GuardError> {
    let name = |part: Message<'a>| match part.of {
        NodeType::String => Ok(part.text(number::STRING_SVAL)?),
        _ => Err(CALLS),
    };
    parts.into_iter().map(name).collect()
}

/// Any relation, read or written, against the schema and relation lists.
fn check_relation(relation: Message<'_>) -> Result<(), GuardError> {
    for qualifier in [number::RANGEVAR_CATALOGNAME, number::RANGEVAR_SCHEMANAME] {
        if let Some(label) = denied_schema(relation.text(qualifier)?) {
            return Err(GuardError::DeniedRelation(label));
        }
    }
    match denied_relation(relation.text(number::RANGEVAR_RELNAME)?) {
        Some(denied) => Err(GuardError::DeniedRelation(denied)),
        None => Ok(()),
    }
}

/// `t.f` and `t.col.f` call `f` when there is no such column; the same rule
/// as the visitor's for sqlparser's compound identifiers.
fn check_column(column: Message<'_>) -> Result<(), GuardError> {
    let parts = column.nodes(number::COLUMNREF_FIELDS)?;
    let (Some(last), 2..) = (parts.last(), parts.len()) else {
        return Ok(());
    };
    if last.of != NodeType::String {
        return Ok(());
    }
    let name = last.text(number::STRING_SVAL)?;
    refuse_function(match parts.len() {
        2 => denied_whole_row_call(name),
        _ => denied_function(name),
    })
}

/// `(x).f` calls `f` when there is no such column.
fn check_attributes(access: Message<'_>) -> Result<(), GuardError> {
    for part in access.nodes(number::AINDIRECTION_INDIRECTION)? {
        if part.of == NodeType::String {
            refuse_function(denied_function(part.text(number::STRING_SVAL)?))?;
        }
    }
    Ok(())
}

/// `pg_settings` has an `UPDATE` rule that calls `set_config`.
fn check_update_target(update: Message<'_>) -> Result<(), GuardError> {
    for target in update.messages(number::UPDATESTMT_RELATION, NodeType::RangeVar)? {
        if target.text(number::RANGEVAR_RELNAME)? == "pg_settings" {
            return Err(GuardError::DeniedFunction("set_config"));
        }
    }
    Ok(())
}

fn refuse_function(denied: Option<&'static str>) -> Result<(), GuardError> {
    match denied {
        Some(denied) => Err(GuardError::DeniedFunction(denied)),
        None => Ok(()),
    }
}
