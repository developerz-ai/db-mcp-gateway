//! The audit export's keyset page query and its per-row width bound.

/// The keyset `page`, kept up to and including the row whose `width` crosses
/// `$12` bytes (the first row always); `page_rows` says if it was cut.
///
/// `width` is an upper bound on the NDJSON line `row_json` emits for
/// the row, so the bytes a batch buffers never pass `$12` plus one row:
/// - text columns: 6 × `octet_length` (read from the stored header, no
///   detoast). serde_json escapes only `"`, `\` (2 bytes) and control
///   characters (at most 6, `\u00XX`); non-ASCII stays as its UTF-8 bytes.
/// - `params` / `groups` (jsonb): `octet_length` of their text form, since a
///   compressed stored size bounds nothing. jsonb text is serde_json's
///   compact form plus a space after every `,` and `:`, with the same string
///   escapes; a number re-renders at most one byte longer (an integer past
///   `u64`, shown as `f64`), and each number but one has a spare separator.
///   `params` is stored capped at `AUDIT_SQL_MAX_BYTES`, so rendering it is
///   bounded too.
/// - 1024 fixed bytes for the rest, about twice their widest: 24 keys with
///   quotes, `:` and `,` (300), braces and newline (3), the UUID and
///   timestamp (70), three `i64` (60), two booleans (10), and quotes or
///   `null` for the 17 nullable text and jsonb values (68).
///
/// Sizing never serializes a full row: the state DB also carries the
/// synchronous audit writes.
pub(super) const SELECT: &str = "WITH page AS (SELECT id, request_id, occurred_at, user_sub, user_email, groups, tool, \
        server_name, database_name, \
        CASE WHEN $9::bool THEN sql END AS sql, \
        CASE WHEN $9::bool THEN sql_truncated END AS sql_truncated, \
        CASE WHEN $9::bool THEN params END AS params, \
        reason, outcome, elapsed_ms, row_count, truncated, rows_affected, error_message, \
        agent_client, ip, db_type, upstream_actor, upstream_run_id \
     FROM audit_calls \
     WHERE ($1::text IS NULL OR user_sub = $1 OR user_email = $1) \
       AND ($2::text IS NULL OR server_name = $2) \
       AND ($3::text IS NULL OR database_name = $3) \
       AND ($4::text IS NULL OR tool = $4) \
       AND ($5::text IS NULL OR outcome = $5) \
       AND ($6::timestamptz IS NULL OR occurred_at >= $6) \
       AND ($7::timestamptz IS NULL OR occurred_at < $7) \
       AND ($10::timestamptz IS NULL OR (occurred_at, id) < ($10, $11)) \
     ORDER BY occurred_at DESC, id DESC LIMIT $8), \
     sized AS (SELECT page.*, 1024 \
        + 6 * (coalesce(octet_length(request_id), 0::bigint) + coalesce(octet_length(user_sub), 0) \
          + coalesce(octet_length(user_email), 0) + coalesce(octet_length(tool), 0) \
          + coalesce(octet_length(server_name), 0) + coalesce(octet_length(database_name), 0) \
          + coalesce(octet_length(sql), 0) + coalesce(octet_length(reason), 0) \
          + coalesce(octet_length(outcome), 0) + coalesce(octet_length(error_message), 0) \
          + coalesce(octet_length(agent_client), 0) + coalesce(octet_length(ip), 0) \
          + coalesce(octet_length(db_type), 0) + coalesce(octet_length(upstream_actor), 0) \
          + coalesce(octet_length(upstream_run_id), 0)) \
        + coalesce(octet_length(params::text), 0) + coalesce(octet_length(groups::text), 0) AS width \
        FROM page), \
     framed AS (SELECT sized.*, count(*) OVER () AS page_rows, \
        coalesce(sum(width) OVER (ORDER BY occurred_at DESC, id DESC \
          ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0) AS before FROM sized) \
     SELECT * FROM framed WHERE before < $12 ORDER BY occurred_at DESC, id DESC";
