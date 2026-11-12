//! `describe_schema` SQL: one row per column from `information_schema`.

/// Build the catalog query + the bind values that go with it. Schema and
/// table go through `$1` / `$2` — they're values, not identifiers, in this
/// query, so the standard parameterised path is safe.
pub(super) fn columns_query<'a>(schema: &'a str, table: Option<&'a str>) -> (String, Vec<&'a str>) {
    let base = "SELECT table_schema, table_name, column_name, data_type, is_nullable \
                FROM information_schema.columns \
                WHERE table_schema = $1";
    let order = " ORDER BY table_name, ordinal_position";
    match table {
        Some(table) => (
            format!("{base} AND table_name = $2{order}"),
            vec![schema, table],
        ),
        None => (format!("{base}{order}"), vec![schema]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_query_uses_bind_params() {
        let (sql, binds) = columns_query("public", None);
        assert!(sql.contains("table_schema = $1"), "{sql}");
        assert!(!sql.contains("AND table_name"), "{sql}");
        assert!(
            sql.ends_with("ORDER BY table_name, ordinal_position"),
            "{sql}"
        );
        assert_eq!(binds, vec!["public"]);

        let (sql, binds) = columns_query("acme", Some("users"));
        assert!(sql.contains("table_schema = $1"));
        assert!(sql.contains("AND table_name = $2"));
        assert_eq!(binds, vec!["acme", "users"]);
    }
}
