//! Mongo's `describe_schema` shape: one entry per collection with its
//! indexes. The adapter answers one row per collection,
//! `[database, collection, type, indexes]` (see `DbAdapter::describe_schema`).

use serde::Serialize;
use serde_json::Value;

use crate::exec::ExecResult;

#[derive(Debug, Serialize)]
pub(super) struct CollectionView {
    database: String,
    name: String,
    /// `collection`, `view`, `timeseries`, …
    #[serde(rename = "type")]
    kind: String,
    /// `{name, key, unique}` per index, passed through; empty for a view.
    indexes: Value,
}

#[derive(Debug, Serialize)]
pub(super) struct DescribeCollectionsResult {
    pub(super) collections: Vec<CollectionView>,
    /// The listing hit the catalog row cap; collections past it are missing.
    truncated: bool,
}

pub(super) fn assemble_collections(result: &ExecResult) -> Result<DescribeCollectionsResult, ()> {
    let collections = result
        .rows
        .iter()
        .map(|row| match row.as_slice() {
            [database, name, kind, indexes @ Value::Array(_)] => Ok(CollectionView {
                database: database.as_str().ok_or(())?.to_owned(),
                name: name.as_str().ok_or(())?.to_owned(),
                kind: kind.as_str().ok_or(())?.to_owned(),
                indexes: indexes.clone(),
            }),
            _ => Err(()),
        })
        .collect::<Result<_, ()>>()?;
    Ok(DescribeCollectionsResult {
        collections,
        truncated: result.truncated,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn result(rows: Vec<Vec<Value>>) -> ExecResult {
        ExecResult {
            columns: vec![
                "database".into(),
                "collection".into(),
                "type".into(),
                "indexes".into(),
            ],
            rows,
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        }
    }

    #[test]
    fn collections_carry_their_indexes() {
        let indexes = json!([{ "name": "_id_", "key": { "_id": 1 }, "unique": true }]);
        let rows = vec![vec![
            json!("app"),
            json!("orders"),
            json!("collection"),
            indexes.clone(),
        ]];
        let assembled = assemble_collections(&result(rows)).expect("assembles");
        let rendered = serde_json::to_value(&assembled).unwrap();
        assert_eq!(rendered["collections"][0]["name"], "orders");
        assert_eq!(rendered["collections"][0]["type"], "collection");
        assert_eq!(rendered["collections"][0]["indexes"], indexes);
        assert_eq!(rendered["truncated"], false);
    }

    #[test]
    fn an_unexpected_row_shape_is_an_error() {
        let rows = vec![vec![json!("app"), json!("orders"), json!("collection")]];
        assert!(assemble_collections(&result(rows)).is_err());
        let rows = vec![vec![json!("app"), json!(1), json!("view"), json!([])]];
        assert!(assemble_collections(&result(rows)).is_err());
    }
}
