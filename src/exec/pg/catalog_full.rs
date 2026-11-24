//! The `detail: full` select list: one row per relation, its columns, keys
//! and indexes as JSON built by the server. Fixed text, no placeholder — the
//! filters `catalog::schema_query` appends bind every value.
//!
//! Columns are filtered the way `information_schema.columns` filters them
//! (owner, or a privilege on the column); a foreign key is listed only when
//! the role can see the referenced relation too.

/// `[schema, table, kind, comment, row_estimate, columns, primary_key,
/// foreign_keys, indexes]`. `row_estimate` is `reltuples`, `NULL` for a view
/// or a table never analysed; `columns` is
/// `[{name, data_type, nullable, default?, comment?, element_type?,
/// enum_values?}]` with `data_type` from `format_type`; `primary_key` a
/// column-name array or `NULL`; `foreign_keys`
/// `[{name, columns, references: {schema, table, columns}}]`; `indexes`
/// `[{name, columns, unique, primary, definition}]`, an expression key
/// column `null`.
pub(super) const FULL_SELECT: &str = "SELECT n.nspname::text AS schema, c.relname::text AS table, \
     CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned_table' \
       WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' \
       WHEN 'f' THEN 'foreign_table' END AS kind, \
     obj_description(c.oid, 'pg_class') AS comment, \
     CASE WHEN c.relkind IN ('r', 'p', 'm') AND c.reltuples >= 0 \
       THEN c.reltuples::int8 END AS row_estimate, \
     COALESCE((SELECT json_agg(json_strip_nulls(json_build_object( \
         'name', a.attname, \
         'data_type', format_type(a.atttypid, a.atttypmod), \
         'nullable', NOT a.attnotnull, \
         'default', pg_get_expr(d.adbin, d.adrelid), \
         'comment', col_description(c.oid, a.attnum), \
         'element_type', CASE WHEN t.typcategory = 'A' THEN format_type(t.typelem, NULL) END, \
         'enum_values', (SELECT json_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_enum e \
           WHERE e.enumtypid = CASE WHEN t.typcategory = 'A' THEN t.typelem ELSE t.oid END) \
       )) ORDER BY a.attnum) \
       FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid \
       LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
       WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped \
       AND (pg_has_role(c.relowner, 'USAGE') \
         OR has_column_privilege(c.oid, a.attnum, 'SELECT, INSERT, UPDATE, REFERENCES'))), \
       '[]'::json) AS columns, \
     (SELECT json_agg(a.attname ORDER BY k.ord) \
       FROM pg_constraint p, unnest(p.conkey) WITH ORDINALITY k(attnum, ord) \
       JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum \
       WHERE p.conrelid = c.oid AND p.contype = 'p') AS primary_key, \
     COALESCE((SELECT json_agg(json_build_object( \
         'name', f.conname, \
         'columns', (SELECT json_agg(a.attname ORDER BY k.ord) \
           FROM unnest(f.conkey) WITH ORDINALITY k(attnum, ord) \
           JOIN pg_attribute a ON a.attrelid = f.conrelid AND a.attnum = k.attnum), \
         'references', json_build_object('schema', rn.nspname, 'table', r.relname, \
           'columns', (SELECT json_agg(a.attname ORDER BY k.ord) \
             FROM unnest(f.confkey) WITH ORDINALITY k(attnum, ord) \
             JOIN pg_attribute a ON a.attrelid = f.confrelid AND a.attnum = k.attnum)) \
       ) ORDER BY f.conname) \
       FROM pg_constraint f JOIN pg_class r ON r.oid = f.confrelid \
       JOIN pg_namespace rn ON rn.oid = r.relnamespace \
       WHERE f.conrelid = c.oid AND f.contype = 'f' \
       AND (pg_has_role(r.relowner, 'USAGE') \
         OR has_any_column_privilege(r.oid, 'SELECT, INSERT, UPDATE, REFERENCES'))), \
       '[]'::json) AS foreign_keys, \
     COALESCE((SELECT json_agg(json_build_object( \
         'name', ic.relname, \
         'columns', (SELECT json_agg(a.attname ORDER BY k.ord) \
           FROM unnest(i.indkey::int2[]) WITH ORDINALITY k(attnum, ord) \
           LEFT JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum \
           WHERE k.ord <= i.indnkeyatts), \
         'unique', i.indisunique, \
         'primary', i.indisprimary, \
         'definition', pg_get_indexdef(i.indexrelid) \
       ) ORDER BY ic.relname) \
       FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid \
       WHERE i.indrelid = c.oid), '[]'::json) AS indexes";
