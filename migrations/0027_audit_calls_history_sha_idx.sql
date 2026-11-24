-- A `get_query_history` lookup by `sql_sha256` seeks the caller's rows with
-- that digest and reads them in page order, instead of hashing every row of
-- the caller's history (0026 adds the column).
--
-- Not CONCURRENTLY, as 0011: production `audit_calls` is small under the
-- 90-day retention, so the build lock is momentary.

CREATE INDEX audit_calls_history_sha_idx
    ON audit_calls (user_sub, server_name, database_name, sql_sha256, occurred_at DESC, id DESC);
