//! Introspection SQL: `table_stats`, `db_activity`, and the cancel by
//! gateway request id. All of it reads statistics views the gateway's own
//! roles can see without extra privileges; none of it needs a superuser.

use std::time::Duration;

use sqlx::Row;
use uuid::Uuid;

use super::super::adapter::{ExecError, ExecResult};
use super::POOL_ACQUIRE_TIMEOUT;
use super::cancel::BackendTag;
use super::error::classify;
use super::tier::{Tier, TierKind};

/// Statistics for every table in `schema` (or just `table`) the read role
/// may `SELECT`: the statistics views list every table in the database, and
/// table scoping belongs to the role's grants. Schema and table are bound.
pub(super) fn table_stats_query<'a>(
    schema: &'a str,
    table: Option<&'a str>,
) -> (String, Vec<&'a str>) {
    let base = "SELECT t.schemaname::text AS schema, t.relname::text AS table, \
                pg_total_relation_size(t.relid) AS total_bytes, \
                pg_relation_size(t.relid) AS table_bytes, \
                pg_indexes_size(t.relid) AS index_bytes, \
                c.reltuples::int8 AS row_estimate, \
                t.n_live_tup AS live_rows, t.n_dead_tup AS dead_rows, \
                t.seq_scan AS seq_scans, t.idx_scan AS index_scans, \
                t.last_vacuum, t.last_autovacuum, t.last_analyze, t.last_autoanalyze, \
                COALESCE((SELECT jsonb_agg(jsonb_build_object( \
                    'name', i.indexrelname, \
                    'bytes', pg_relation_size(i.indexrelid), \
                    'scans', i.idx_scan) ORDER BY i.indexrelname) \
                  FROM pg_stat_user_indexes i WHERE i.relid = t.relid), '[]'::jsonb) AS indexes \
                FROM pg_stat_user_tables t JOIN pg_class c ON c.oid = t.relid \
                WHERE t.schemaname = $1 AND has_table_privilege(t.relid, 'SELECT')";
    let order = " ORDER BY t.relname";
    match table {
        Some(table) => (
            format!("{base} AND t.relname = $2{order}"),
            vec![schema, table],
        ),
        None => (format!("{base}{order}"), vec![schema]),
    }
}

/// The non-idle backends of the tier's role on this database, minus the
/// backend running this query. The request id is read back out of the
/// [`BackendTag`] in `application_name`. The `pool` literal is a
/// [`TierKind::label`], a fixed word.
pub(super) fn activity_sql(kind: TierKind) -> String {
    format!(
        "SELECT pid, \
         substring(application_name from '{pattern}')::uuid AS request_id, \
         '{pool}' AS pool, state, wait_event_type, wait_event, \
         (extract(epoch from clock_timestamp() - query_start) * 1000)::int8 AS running_ms \
         FROM pg_stat_activity \
         WHERE usename = current_user AND datname = current_database() \
         AND pid <> pg_backend_pid() AND state <> 'idle' \
         ORDER BY query_start",
        pattern = BackendTag::REQUEST_ID_PATTERN,
        pool = kind.label(),
    )
}

/// One `db_activity` answer from both tiers, still capped at `row_limit`.
pub(super) fn merge_activity(read: ExecResult, write: ExecResult, row_limit: u32) -> ExecResult {
    let cap = usize::try_from(row_limit).unwrap_or(usize::MAX);
    let mut rows = read.rows;
    rows.extend(write.rows);
    let over = rows.len() > cap;
    rows.truncate(cap);
    ExecResult {
        columns: read.columns,
        rows,
        truncated: read.truncated || write.truncated || over,
        elapsed_ms: read.elapsed_ms + write.elapsed_ms,
        rows_affected: None,
    }
}

/// Signal every backend of the tier's role that carries `request_id`'s tag.
/// Runs on the cancel pool, so it is never queued behind the query it
/// targets. `pg_cancel_backend` on an own-role backend needs no privilege.
const CANCEL_BY_TAG_SQL: &str = "SELECT count(*) FILTER (WHERE pg_cancel_backend(pid)) \
                                 FROM pg_stat_activity \
                                 WHERE usename = current_user AND application_name LIKE $1";

pub(super) async fn cancel_request(tier: &Tier, request_id: Uuid) -> Result<bool, ExecError> {
    let pattern = format!("{}%", BackendTag::request_prefix(request_id));
    let cancel = sqlx::query(CANCEL_BY_TAG_SQL)
        .bind(pattern)
        .fetch_one(&tier.cancel_pool);
    // The acquire is bounded by the pool; the round trip itself by this.
    let budget = POOL_ACQUIRE_TIMEOUT + Duration::from_secs(5);
    let row = match tokio::time::timeout(budget, cancel).await {
        Ok(row) => row.map_err(|err| classify(err, &tier.role))?,
        Err(_elapsed) => return Err(ExecError::Timeout),
    };
    let signalled: i64 = row.try_get(0).map_err(|err| classify(err, &tier.role))?;
    Ok(signalled > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_stats_binds_schema_and_table() {
        let (sql, binds) = table_stats_query("public", None);
        assert!(sql.contains("t.schemaname = $1"), "{sql}");
        assert!(sql.contains("has_table_privilege"), "{sql}");
        assert!(!sql.contains("$2"), "{sql}");
        assert_eq!(binds, vec!["public"]);

        let (sql, binds) = table_stats_query("acme", Some("users"));
        assert!(sql.contains("t.relname = $2"), "{sql}");
        assert_eq!(binds, vec!["acme", "users"]);
    }

    #[test]
    fn activity_is_scoped_to_the_own_role_and_labelled_by_pool() {
        let sql = activity_sql(TierKind::Write);
        assert!(sql.contains("usename = current_user"), "{sql}");
        assert!(sql.contains("pid <> pg_backend_pid()"), "{sql}");
        assert!(sql.contains("'write' AS pool"), "{sql}");
        assert!(!sql.contains(" query,"), "no query text: {sql}");
    }

    fn result(rows: usize, truncated: bool) -> ExecResult {
        ExecResult {
            columns: vec!["pid".into()],
            rows: (0..rows).map(|i| vec![serde_json::json!(i)]).collect(),
            truncated,
            elapsed_ms: 1,
            rows_affected: None,
        }
    }

    #[test]
    fn merged_activity_keeps_the_row_cap() {
        let merged = merge_activity(result(2, false), result(2, false), 3);
        assert_eq!(merged.rows.len(), 3);
        assert!(merged.truncated);
        let merged = merge_activity(result(1, false), result(1, false), 3);
        assert_eq!(merged.rows.len(), 2);
        assert!(!merged.truncated);
    }
}
