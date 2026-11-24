//! `describe_schema` SQL, one statement per [`SchemaDetail`]. Schema, table
//! and search term reach the catalog as bound values (`$1`, `$2`, …), never
//! as text: the only interpolation is the placeholder number.
//!
//! Visibility matches `information_schema`: a relation is listed when the
//! read role owns it or holds a privilege on one of its columns, a column
//! when the role owns its relation or holds a privilege on it. A search
//! term matches a column only under that same column rule.

use super::super::query::{SchemaDetail, SchemaQuery};
use super::catalog_full::FULL_SELECT;

/// Schemas the role may use, system schemas aside.
const SCHEMAS_SQL: &str = "SELECT n.nspname::text AS schema FROM pg_namespace n \
     WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_' \
     AND has_schema_privilege(n.oid, 'USAGE') ORDER BY 1";

const COLUMNS_SELECT: &str = "SELECT c.table_schema, c.table_name, c.column_name, c.data_type, c.is_nullable \
     FROM information_schema.columns c WHERE true";

const NAMES_SELECT: &str = "SELECT n.nspname::text AS schema, c.relname::text AS table, \
     CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned_table' \
       WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' \
       WHEN 'f' THEN 'foreign_table' END AS kind";

/// The `FROM` + visibility filter shared by the `names` and `full` shapes.
const RELATIONS_FROM: &str = " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') \
     AND has_schema_privilege(n.oid, 'USAGE') \
     AND (pg_has_role(c.relowner, 'USAGE') \
       OR has_any_column_privilege(c.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))";

/// The catalog statement for `query` and the values bound to it, in order.
pub(super) fn schema_query<'a>(query: &SchemaQuery<'a>) -> (String, Vec<&'a str>) {
    let mut sql = Bound::default();
    match query.detail {
        SchemaDetail::Schemas => sql.text.push_str(SCHEMAS_SQL),
        SchemaDetail::Columns => {
            sql.text.push_str(COLUMNS_SELECT);
            sql.schema_filter("c.table_schema", query.schema);
            sql.filter("c.table_name", query.table);
            if let Some(term) = query.search {
                let term = sql.bind(term);
                sql.text.push_str(&format!(
                    " AND (strpos(lower(c.table_name), lower({term})) > 0 \
                     OR EXISTS (SELECT 1 FROM information_schema.columns m \
                       WHERE m.table_schema = c.table_schema AND m.table_name = c.table_name \
                       AND strpos(lower(m.column_name), lower({term})) > 0))"
                ));
            }
            sql.text
                .push_str(" ORDER BY c.table_schema, c.table_name, c.ordinal_position");
        }
        SchemaDetail::Names | SchemaDetail::Full => {
            sql.text.push_str(match query.detail {
                SchemaDetail::Full => FULL_SELECT,
                _ => NAMES_SELECT,
            });
            sql.text.push_str(RELATIONS_FROM);
            sql.schema_filter("n.nspname", query.schema);
            sql.filter("c.relname", query.table);
            if let Some(term) = query.search {
                let term = sql.bind(term);
                sql.text.push_str(&format!(
                    " AND (strpos(lower(c.relname), lower({term})) > 0 \
                     OR EXISTS (SELECT 1 FROM pg_attribute m WHERE m.attrelid = c.oid \
                       AND m.attnum > 0 AND NOT m.attisdropped \
                       AND (pg_has_role(c.relowner, 'USAGE') \
                         OR has_column_privilege(c.oid, m.attnum, 'SELECT, INSERT, UPDATE, REFERENCES')) \
                       AND strpos(lower(m.attname), lower({term})) > 0))"
                ));
            }
            sql.text.push_str(" ORDER BY n.nspname, c.relname");
        }
    }
    (sql.text, sql.binds)
}

/// A statement under construction and its bound values.
#[derive(Default)]
struct Bound<'a> {
    text: String,
    binds: Vec<&'a str>,
}

impl<'a> Bound<'a> {
    /// The placeholder `value` is bound to.
    fn bind(&mut self, value: &'a str) -> String {
        self.binds.push(value);
        format!("${}", self.binds.len())
    }

    /// `column = value`, when there is a value.
    fn filter(&mut self, column: &'static str, value: Option<&'a str>) {
        if let Some(value) = value {
            let at = self.bind(value);
            self.text.push_str(&format!(" AND {column} = {at}"));
        }
    }

    /// `column = schema`; with no schema, every schema but the system ones.
    fn schema_filter(&mut self, column: &'static str, schema: Option<&'a str>) {
        match schema {
            Some(_) => self.filter(column, schema),
            None => self.text.push_str(&format!(
                " AND {column} <> 'information_schema' AND {column} !~ '^pg_'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn query<'a>(
        detail: SchemaDetail,
        schema: Option<&'a str>,
        table: Option<&'a str>,
        search: Option<&'a str>,
    ) -> SchemaQuery<'a> {
        SchemaQuery {
            schema,
            table,
            search,
            detail,
            statement_timeout_ms: None,
            row_limit: 10,
            sample_limit: 0,
            request_id: Uuid::nil(),
        }
    }

    #[test]
    fn the_default_shape_binds_schema_and_table() {
        let (sql, binds) = schema_query(&query(SchemaDetail::Columns, Some("public"), None, None));
        assert!(sql.contains("c.table_schema = $1"), "{sql}");
        assert!(!sql.contains("c.table_name ="), "{sql}");
        assert!(
            sql.ends_with("ORDER BY c.table_schema, c.table_name, c.ordinal_position"),
            "{sql}"
        );
        assert_eq!(binds, vec!["public"]);

        let q = query(SchemaDetail::Columns, Some("acme"), Some("users"), None);
        let (sql, binds) = schema_query(&q);
        assert!(sql.contains("c.table_schema = $1"));
        assert!(sql.contains("c.table_name = $2"));
        assert_eq!(binds, vec!["acme", "users"]);
    }

    #[test]
    fn search_and_schema_are_bound_never_spliced() {
        let hostile = "x' OR 1=1 --";
        for detail in [
            SchemaDetail::Columns,
            SchemaDetail::Names,
            SchemaDetail::Full,
        ] {
            let (sql, binds) = schema_query(&query(detail, None, Some(hostile), Some(hostile)));
            assert!(!sql.contains(hostile), "{detail:?}: {sql}");
            assert_eq!(binds, vec![hostile, hostile], "{detail:?}");
            assert!(sql.contains("lower($2)"), "{detail:?}: {sql}");
            assert!(
                sql.contains("!~ '^pg_'"),
                "every schema but the system ones: {sql}"
            );
        }
    }

    #[test]
    fn the_schema_list_binds_nothing() {
        let (sql, binds) = schema_query(&query(SchemaDetail::Schemas, Some("x"), None, Some("y")));
        assert_eq!(sql, SCHEMAS_SQL);
        assert!(binds.is_empty());
    }
}
