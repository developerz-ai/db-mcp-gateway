//! `sample_table`'s `columns` argument: keep only the named columns, in the
//! caller's order. On Mongo a sample is one `document` column, so the names
//! pick top-level fields of each document instead.

use serde_json::{Map, Value};

use crate::config::ServerKind;
use crate::exec::ExecResult;

/// Keep only `wanted` in `result`. `Err` lists the names the result has no
/// column for, leaving `result` as it was (never on Mongo: a document may
/// simply lack a field).
pub(in crate::tools) fn project(
    kind: ServerKind,
    result: &mut ExecResult,
    wanted: &[&str],
) -> Result<(), Vec<String>> {
    if kind == ServerKind::Mongo {
        for doc in result.rows.iter_mut().flatten() {
            *doc = pick_fields(std::mem::take(doc), wanted);
        }
        return Ok(());
    }
    let mut indices = Vec::with_capacity(wanted.len());
    let mut missing = Vec::new();
    for name in wanted {
        match result.columns.iter().position(|column| column == name) {
            Some(index) => indices.push(index),
            None => missing.push((*name).to_owned()),
        }
    }
    if !missing.is_empty() {
        return Err(missing);
    }
    result.columns = pick(&result.columns, &indices);
    // Empty on a backend without type info; `pick` keeps it empty.
    result.column_types = pick(&result.column_types, &indices);
    for row in &mut result.rows {
        *row = pick(row, &indices);
    }
    Ok(())
}

fn pick<T: Clone>(items: &[T], indices: &[usize]) -> Vec<T> {
    indices
        .iter()
        .filter_map(|&i| items.get(i).cloned())
        .collect()
}

fn pick_fields(doc: Value, wanted: &[&str]) -> Value {
    let Value::Object(mut fields) = doc else {
        return doc;
    };
    let picked: Map<String, Value> = wanted
        .iter()
        .filter_map(|name| fields.remove_entry(*name))
        .collect();
    Value::Object(picked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn result(columns: &[&str], rows: Vec<Vec<Value>>) -> ExecResult {
        ExecResult {
            columns: columns.iter().map(|c| (*c).to_owned()).collect(),
            column_types: Vec::new(),
            rows,
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        }
    }

    fn table() -> ExecResult {
        result(
            &["id", "name", "email"],
            vec![vec![json!(1), json!("ada"), json!("a@x")]],
        )
    }

    #[test]
    fn keeps_named_columns_in_the_callers_order() {
        let mut table = table();
        table.column_types = ["int4", "text", "varchar"].map(String::from).to_vec();
        project(ServerKind::Postgres, &mut table, &["email", "id"]).unwrap();
        assert_eq!(table.columns, ["email", "id"]);
        assert_eq!(table.column_types, ["varchar", "int4"]);
        assert_eq!(table.rows, vec![vec![json!("a@x"), json!(1)]]);
    }

    #[test]
    fn names_every_unknown_column_and_keeps_the_result() {
        let mut table = table();
        let missing = project(ServerKind::Postgres, &mut table, &["id", "nope", "nah"]);
        assert_eq!(missing.unwrap_err(), ["nope", "nah"]);
        assert_eq!(table.columns, ["id", "name", "email"]);
    }

    #[test]
    fn mongo_picks_document_fields() {
        let rows = vec![
            vec![json!({"_id": 1, "name": "ada", "secret": "x"})],
            vec![json!({"_id": 2})],
        ];
        let mut docs = result(&["document"], rows);
        project(ServerKind::Mongo, &mut docs, &["name", "_id"]).unwrap();
        assert_eq!(docs.columns, ["document"]);
        assert_eq!(docs.rows[0][0], json!({"name": "ada", "_id": 1}));
        assert_eq!(docs.rows[1][0], json!({"_id": 2}));
    }
}
