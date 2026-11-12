//! `explain` SQL: `EXPLAIN (FORMAT JSON)` around an already-guarded
//! statement. Plain `EXPLAIN` plans without running, so a data write may be
//! explained; `ANALYZE` runs the statement and is built only for a read,
//! which the adapter then runs in a read-only transaction under the
//! statement timeout.

use super::super::adapter::ExecError;
use super::super::sql_guard::{Access, GuardedSql};

/// EXPLAIN always returns a tiny result (one row, one column containing the
/// plan JSON). A row cap exists only as a sanity bound — should never trip.
pub(super) const EXPLAIN_RESULT_CAP: u32 = 100;

/// Wrapping is safe only because `sql` already passed the guard; the
/// `GuardedSql` type is the proof. Postgres returns one row, one column
/// ("QUERY PLAN") holding the plan as JSON.
pub(super) fn explain_sql(sql: GuardedSql<'_>, analyze: bool) -> Result<String, ExecError> {
    if !analyze {
        return Ok(format!("EXPLAIN (FORMAT JSON) {}", sql.as_str()));
    }
    if sql.required_access() != Access::ReadOnly {
        return Err(ExecError::Forbidden(
            "EXPLAIN ANALYZE runs the statement; it is allowed for read statements only"
                .to_string(),
        ));
    }
    Ok(format!("EXPLAIN (ANALYZE, FORMAT JSON) {}", sql.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guarded(sql: &str, access: Access) -> GuardedSql<'_> {
        GuardedSql::parse(sql, access).expect("guarded")
    }

    #[test]
    fn wraps_guarded_sql_without_analyze() {
        let sql = guarded("SELECT 1", Access::ReadOnly);
        assert_eq!(
            explain_sql(sql, false).expect("plain"),
            "EXPLAIN (FORMAT JSON) SELECT 1"
        );
    }

    #[test]
    fn analyze_wraps_a_read() {
        let sql = guarded("SELECT 1", Access::ReadWrite);
        assert_eq!(
            explain_sql(sql, true).expect("analyze"),
            "EXPLAIN (ANALYZE, FORMAT JSON) SELECT 1"
        );
    }

    #[test]
    fn a_write_is_planned_but_never_analyzed() {
        let sql = guarded("DELETE FROM t WHERE id = 1", Access::ReadWrite);
        assert_eq!(
            explain_sql(sql, false).expect("plain"),
            "EXPLAIN (FORMAT JSON) DELETE FROM t WHERE id = 1"
        );
        assert!(matches!(
            explain_sql(sql, true),
            Err(ExecError::Forbidden(_))
        ));
    }
}
