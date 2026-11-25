//! The tree as the `pg_query` crate decodes it, to hold the wire walk against.
//! Shallow statements only: its decoder stops at 100 levels.

use std::collections::BTreeMap;

use serde_json::Value;

/// How many messages the one statement's tree holds, `Node`s left out; and
/// of each type a `Node` names, how many, by its lower-cased name.
pub(super) fn messages(sql: &str) -> Option<(usize, BTreeMap<String, usize>)> {
    let parsed = pg_query::parse(sql, 0).ok()?;
    let [raw] = parsed.protobuf.stmts.as_slice() else {
        return None;
    };
    let tree = serde_json::to_value(&raw.stmt).ok()?;
    let mut named = BTreeMap::new();
    let count = count(&tree, &mut named);
    Some((usize::try_from(count).ok()?, named))
}

fn count(value: &Value, named: &mut BTreeMap<String, usize>) -> isize {
    match value {
        Value::Object(map) => {
            let mut here = 1;
            // A `Node` is an object of one field, which holds an object
            // keyed by the node's type, or null.
            if let (1, Some(node)) = (map.len(), map.get("node")) {
                here -= 1;
                if let Some((name, _)) = node.as_object().and_then(|of| of.iter().next()) {
                    here -= 1;
                    *named.entry(name.to_lowercase()).or_default() += 1;
                }
            }
            // `A_Const`'s value is keyed by its type too.
            if map.contains_key("isnull") && map.get("val").is_some_and(|v| !v.is_null()) {
                here -= 1;
            }
            here + map.values().map(|v| count(v, named)).sum::<isize>()
        }
        Value::Array(items) => items.iter().map(|v| count(v, named)).sum(),
        _ => 0,
    }
}
