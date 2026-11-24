//! The names the guard refuses whatever the Postgres role may do.

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
///   `pg_ls_*` (every directory listing), `pg_current_logfile`, adminpack's
///   `pg_file_*` and `pg_logdir_ls`, and the large-object family `lo_*` /
///   `loread` / `lowrite` (`lo_export` writes a server file; `lo_from_bytea`
///   creates an object — no side effect is allowed from a read).
/// - session state: `set_config` (a session-level change would outlive the
///   query on a pooled connection) and every advisory lock function (a
///   session lock blocks other users until the connection is reset).
/// - other backends: `pg_cancel_backend`, `pg_terminate_backend`.
/// - other sessions' statements: `pg_stat_get_activity`,
///   `pg_stat_get_backend_*`, `pg_prepared_statement` — the functions under
///   the views in [`DENIED_RELATIONS`].
/// - shared server state: `pg_stat_reset*` and `pg_stat_statements_reset`
///   wipe statistics every DBA tool reads; `setseed` outlives the query on
///   a pooled connection.
/// - replication: `pg_logical_slot_*` (`get`/`peek` consume or read the
///   change stream — row data of tables the role may not `SELECT`),
///   `pg_replication_slot_advance`, `pg_drop_replication_slot`,
///   `pg_create_*` and `pg_copy_*` (slots, restore points),
///   `pg_replication_origin_*`.
/// - dynamic SQL: `query_to_xml*`, `cursor_to_xml*`, `table_to_xml*`,
///   `schema_to_xml*`, `database_to_xml*`, `ts_stat` and `ts_rewrite` execute
///   SQL text or whole-schema reads the guard cannot inspect — a denied call
///   inside that text runs unseen, as do tablefunc's `crosstab*` and
///   `connectby` and xml2's `xpath_table`; `dblink*` reaches other servers.
/// - network: the `http` extension and pg_net (`http`, `http_get`, …),
///   `aws_lambda.invoke`, `aws_s3.query_export_to_s3` (which also runs SQL
///   text) and `table_import_from_s3`. Exact names, not an `http*` family:
///   a column named `http_status` is ordinary.
///
/// `alias.name` is a call of `name` with the alias's whole row when no such
/// column exists, so a two-part column reference is checked too — against
/// the families and the [`Denied::WholeRow`] names only. An exact name whose
/// signature cannot take one row (`pg_notify(text, text)`,
/// `pg_read_file(text)`) is an ordinary column there.
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
    Denied::Prefix("pg_file_", "pg_file_*"),
    Denied::Exact("pg_logdir_ls"),
    Denied::Exact("lo_export"),
    Denied::Exact("lo_import"),
    Denied::Prefix("lo_", "lo_*"),
    Denied::Exact("loread"),
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
    Denied::Prefix("crosstab", "crosstab*"),
    Denied::Exact("connectby"),
    Denied::Exact("xpath_table"),
    Denied::Prefix("pgr_", "pgr_*"),
    Denied::Prefix("pg_background_", "pg_background_*"),
    Denied::Exact("schedule"),
    Denied::Exact("schedule_in_database"),
    Denied::Exact("alter_job"),
    Denied::Exact("unschedule"),
    Denied::Exact("query_export_to_s3"),
    Denied::Exact("table_import_from_s3"),
    Denied::Exact("invoke"),
    // `http(http_request)`: a subquery row coerces to the request type.
    Denied::WholeRow("http"),
    Denied::Exact("http_get"),
    Denied::Exact("http_post"),
    Denied::Exact("http_put"),
    Denied::Exact("http_patch"),
    Denied::Exact("http_delete"),
    Denied::Exact("http_head"),
    Denied::Exact("http_set_curlopt"),
    Denied::Exact("http_reset_curlopt"),
    Denied::Exact("pg_replication_slot_advance"),
    Denied::Exact("pg_drop_replication_slot"),
    Denied::Prefix("pg_logical_slot_", "pg_logical_slot_*"),
    Denied::Prefix("pg_create_", "pg_create_*"),
    Denied::Prefix("pg_copy_", "pg_copy_*"),
    Denied::Prefix("pg_replication_origin_", "pg_replication_origin_*"),
    Denied::Exact("pg_stat_statements_reset"),
    Denied::Prefix("pg_stat_reset", "pg_stat_reset*"),
    Denied::Exact("setseed"),
    Denied::Exact("pg_stat_get_activity"),
    Denied::Prefix("pg_stat_get_backend_", "pg_stat_get_backend_*"),
    Denied::Exact("pg_prepared_statement"),
    Denied::Exact("yb_pg_stat_get_queries"),
];

/// Relations the gateway never reads for a caller: each row is another
/// session's statement text or plan, and every identity on a `(server,
/// database)` shares one role, so Postgres shows them all. `db_activity`
/// answers the operational question without the text. Refused wherever the
/// name is written — table, function (`pg_stat_statements(true)`) or alias.
/// `pg_stat_statements_info` (eviction count, reset time) stays readable.
const DENIED_RELATIONS: &[Denied] = &[
    Denied::Exact("pg_stat_activity"),
    Denied::Exact("pg_stat_statements"),
    Denied::Exact("pg_prepared_statements"),
    Denied::Exact("pg_stat_monitor"),
    Denied::Exact("yb_terminated_queries"),
    Denied::Exact("citus_stat_activity"),
    Denied::Exact("citus_dist_stat_activity"),
    Denied::Exact("citus_lock_waits"),
    Denied::Exact("citus_stat_statements"),
    Denied::Exact("aurora_stat_activity"),
    Denied::Exact("pg_show_plans"),
    Denied::Exact("pg_store_plans"),
    Denied::Prefix("pg_qualstats", "pg_qualstats*"),
];

/// Schemas whose every function and relation is refused, reported as
/// `<schema>.*`: pg_cron's functions schedule SQL text and its tables hold
/// every scheduled command the shared role owns.
const DENIED_SCHEMAS: &[(&str, &str)] = &[("cron", "cron.*")];

/// One denylist entry. Exact names come first in [`DENIED_FUNCTIONS`] so a
/// well-known name is reported as itself rather than as its family.
#[derive(Debug, Clone, Copy)]
enum Denied {
    Exact(&'static str),
    /// An exact name whose function takes a single row, so `alias.name`
    /// calls it with the alias's whole row.
    WholeRow(&'static str),
    /// `(prefix, label)` — the label is what the error reports.
    Prefix(&'static str, &'static str),
}

/// The denylist entry a call of `name` falls under, as the error reports it.
pub(super) fn denied_function(name: &str) -> Option<&'static str> {
    DENIED_FUNCTIONS.iter().find_map(|d| d.matches(name))
}

/// The denylist entry `alias.name` falls under: the families and the
/// [`Denied::WholeRow`] names — the calls a whole row can reach.
pub(super) fn denied_whole_row_call(name: &str) -> Option<&'static str> {
    DENIED_FUNCTIONS
        .iter()
        .filter(|d| !matches!(d, Denied::Exact(_)))
        .find_map(|d| d.matches(name))
}

pub(super) fn denied_relation(name: &str) -> Option<&'static str> {
    DENIED_RELATIONS.iter().find_map(|d| d.matches(name))
}

/// The label of the denied schema `name` is, if any.
pub(super) fn denied_schema(name: &str) -> Option<&'static str> {
    DENIED_SCHEMAS
        .iter()
        .find_map(|(schema, label)| schema.eq_ignore_ascii_case(name).then_some(*label))
}

impl Denied {
    /// The name to report if `name` matches this entry.
    fn matches(self, name: &str) -> Option<&'static str> {
        match self {
            Self::Exact(exact) | Self::WholeRow(exact) => {
                exact.eq_ignore_ascii_case(name).then_some(exact)
            }
            Self::Prefix(prefix, label) => name
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
                .then_some(label),
        }
    }
}
