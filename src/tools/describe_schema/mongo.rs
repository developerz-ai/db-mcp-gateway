//! Mongo's `describe_schema` shape: one entry per collection. The adapter
//! answers one row per collection, `[database, collection, type]`, plus
//! `indexes` at `columns` and `full`, plus `sample` at `full` (see
//! `DbAdapter::describe_schema`).

use serde::Serialize;
use serde_json::Value;

use crate::exec::ExecResult;

use super::Detail;

/// Why a `full` answer has no `sample`: sampling reads documents.
const SAMPLE_NEEDS_QUERY_READ: &str =
    "fields are inferred from sampled documents, which needs query_read; listed without them";

#[derive(Debug, Serialize)]
struct CollectionView<'a> {
    database: &'a str,
    name: &'a str,
    /// `collection`, `view`, `timeseries`, …
    #[serde(rename = "type")]
    kind: &'a str,
    /// `{name, key, unique}` per index, passed through; empty for a view.
    #[serde(skip_serializing_if = "Option::is_none")]
    indexes: Option<&'a Value>,
    /// `{sampled, fields: [{name, types, count}], truncated}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    sample: Option<&'a Value>,
}

#[derive(Debug, Serialize)]
struct DescribeCollectionsResult<'a> {
    collections: Vec<CollectionView<'a>>,
    /// The listing hit the catalog row cap; collections past it are missing.
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'static str>,
}

/// `(collections listed, payload JSON)`. `omitted`: a `full` call answered
/// at `columns` for want of `query_read`.
pub(super) fn render(
    detail: Detail,
    result: &ExecResult,
    omitted: bool,
) -> Result<(usize, String), ()> {
    let collections = result
        .rows
        .iter()
        .map(|row| collection_view(detail, row))
        .collect::<Result<Vec<_>, ()>>()?;
    let count = collections.len();
    let payload = DescribeCollectionsResult {
        collections,
        truncated: result.truncated,
        note: omitted.then_some(SAMPLE_NEEDS_QUERY_READ),
    };
    serde_json::to_string(&payload)
        .map(|text| (count, text))
        .map_err(|_| ())
}

fn collection_view(detail: Detail, row: &[Value]) -> Result<CollectionView<'_>, ()> {
    let (head, indexes, sample) = match (detail, row) {
        (Detail::Names, [_, _, _]) => (row, None, None),
        (Detail::Columns, [head @ .., indexes @ Value::Array(_)]) => (head, Some(indexes), None),
        (
            Detail::Full,
            [
                head @ ..,
                indexes @ Value::Array(_),
                sample @ Value::Object(_),
            ],
        ) => (head, Some(indexes), Some(sample)),
        _ => return Err(()),
    };
    let [database, name, kind] = head else {
        return Err(());
    };
    Ok(CollectionView {
        database: database.as_str().ok_or(())?,
        name: name.as_str().ok_or(())?,
        kind: kind.as_str().ok_or(())?,
        indexes,
        sample,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn result(rows: Vec<Vec<Value>>) -> ExecResult {
        ExecResult {
            columns: Vec::new(),
            column_types: Vec::new(),
            rows,
            truncated: false,
            elapsed_ms: 0,
            rows_affected: None,
        }
    }

    fn rendered(detail: Detail, rows: Vec<Vec<Value>>, omitted: bool) -> Value {
        let (_, text) = render(detail, &result(rows), omitted).expect("renders");
        serde_json::from_str(&text).expect("JSON")
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
        let rendered = rendered(Detail::Columns, rows, false);
        assert_eq!(rendered["collections"][0]["name"], "orders");
        assert_eq!(rendered["collections"][0]["type"], "collection");
        assert_eq!(rendered["collections"][0]["indexes"], indexes);
        assert_eq!(rendered["truncated"], false);
        assert!(rendered.get("note").is_none());
        assert!(rendered["collections"][0].get("sample").is_none());
    }

    #[test]
    fn names_and_full_shapes() {
        let names = rendered(
            Detail::Names,
            vec![vec![json!("app"), json!("o"), json!("view")]],
            false,
        );
        assert_eq!(
            names["collections"][0],
            json!({ "database": "app", "name": "o", "type": "view" })
        );
        let sample = json!({ "sampled": 1, "fields": [], "truncated": false });
        let full = rendered(
            Detail::Full,
            vec![vec![
                json!("app"),
                json!("o"),
                json!("collection"),
                json!([]),
                sample.clone(),
            ]],
            false,
        );
        assert_eq!(full["collections"][0]["sample"], sample);
        let downgraded = rendered(
            Detail::Columns,
            vec![vec![
                json!("app"),
                json!("o"),
                json!("collection"),
                json!([]),
            ]],
            true,
        );
        assert_eq!(downgraded["note"], SAMPLE_NEEDS_QUERY_READ);
    }

    #[test]
    fn an_unexpected_row_shape_is_an_error() {
        let rows = vec![vec![json!("app"), json!("orders"), json!("collection")]];
        assert!(render(Detail::Columns, &result(rows), false).is_err());
        let rows = vec![vec![json!("app"), json!(1), json!("view"), json!([])]];
        assert!(render(Detail::Columns, &result(rows), false).is_err());
        let rows = vec![vec![json!("app"), json!("o"), json!("view"), json!([])]];
        assert!(render(Detail::Full, &result(rows), false).is_err());
    }
}
