//! `explain` SQL: `EXPLAIN (FORMAT JSON)` around an already-guarded
//! statement. No `ANALYZE` — the statement is planned, never run.

use super::super::sql_guard::ReadOnlySql;

/// EXPLAIN always returns a tiny result (one row, one column containing the
/// plan JSON). A row cap exists only as a sanity bound — should never trip.
pub(super) const EXPLAIN_RESULT_CAP: u32 = 100;

/// Wrapping is safe only because `sql` already passed the read-only guard;
/// the `ReadOnlySql` type is the proof. Postgres returns one row, one column
/// ("QUERY PLAN") holding the plan as JSON.
pub(super) fn explain_sql(sql: ReadOnlySql<'_>) -> String {
    format!("EXPLAIN (FORMAT JSON) {}", sql.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_guarded_sql_without_analyze() {
        let sql = ReadOnlySql::parse("SELECT 1").expect("read-only");
        assert_eq!(explain_sql(sql), "EXPLAIN (FORMAT JSON) SELECT 1");
    }
}
