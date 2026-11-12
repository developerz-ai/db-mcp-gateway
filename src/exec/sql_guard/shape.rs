//! Top-level statement-shape check: which statement families the guard
//! admits at all under a given [`Access`].

use sqlparser::ast::{OnInsert, Set, Statement};

use super::{Access, GuardError};

/// Whether `stmt` is a statement type the guard admits at all under `access`.
/// The substructure — nested writes, locking clauses, `SELECT INTO`, denied
/// functions — is enforced by [`GuardVisitor`] afterwards. Explains have been
/// unwrapped by [`check_sql`].
pub(super) fn check_statement_shape(stmt: &Statement, access: Access) -> Result<(), GuardError> {
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
        Statement::Set(Set::SetTransaction { .. }) => {
            Err(GuardError::NotAllowed("SET TRANSACTION"))
        }
        Statement::Set(_) => Err(GuardError::NotAllowed("SET")),
        Statement::Copy { .. } => Err(GuardError::NotAllowed("COPY")),
        // `DESCRIBE t` / `EXPLAIN t`: not Postgres syntax, so nothing a real
        // client sends — and nothing this guard should pass by default.
        Statement::ExplainTable { .. } => Err(GuardError::NotAllowed("EXPLAIN TABLE")),
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
