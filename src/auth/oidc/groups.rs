//! Reading the groups claim out of a verified ID token.
//!
//! IdPs disagree on its shape: most emit an array of names, Zitadel an object
//! keyed by role name. Anything the gateway cannot read is logged — a user who
//! signs in with no groups sees nothing, and the log line is the only place
//! the operator learns why.

use serde_json::Value;

use super::options::GroupsPrefix;

/// The group names `value` carries, after the optional prefix filter.
/// `claim` is the configured claim name, for the log line only.
pub(super) fn from_claim(
    claim: &str,
    value: Option<&Value>,
    prefix: Option<&GroupsPrefix>,
) -> Vec<String> {
    let names = match value {
        Some(Value::Array(items)) => array_names(claim, items),
        // Zitadel: `{"<role>": {"<org id>": "<org domain>"}}`.
        Some(Value::Object(roles)) => roles.keys().cloned().collect(),
        None | Some(Value::Null) => {
            tracing::info!(
                claim,
                "ID token carries no groups claim; login has no groups"
            );
            Vec::new()
        }
        Some(other) => {
            tracing::warn!(
                claim,
                shape = shape_of(other),
                "groups claim is neither an array nor an object; login has no groups"
            );
            Vec::new()
        }
    };
    match prefix {
        Some(prefix) => strip_prefix(claim, names, prefix.as_str()),
        None => names,
    }
}

fn array_names(claim: &str, items: &[Value]) -> Vec<String> {
    let names: Vec<String> = items
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect();
    let skipped = items.len() - names.len();
    if skipped > 0 {
        tracing::warn!(
            claim,
            skipped,
            "groups claim holds entries that are not strings; they were ignored"
        );
    }
    names
}

/// Keep the groups that start with `prefix`, without it. A group that is the
/// bare prefix would become the empty name, so it is dropped too.
fn strip_prefix(claim: &str, names: Vec<String>, prefix: &str) -> Vec<String> {
    let total = names.len();
    let kept: Vec<String> = names
        .iter()
        .filter_map(|name| name.strip_prefix(prefix))
        .filter(|rest| !rest.is_empty())
        .map(str::to_owned)
        .collect();
    if total > 0 && kept.is_empty() {
        tracing::warn!(
            claim,
            total,
            "no group in the claim starts with OIDC_GROUPS_PREFIX; login has no groups"
        );
    }
    kept
}

fn shape_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CLAIM: &str = "groups";

    fn prefix(raw: &str) -> GroupsPrefix {
        GroupsPrefix::parse(raw).expect("valid prefix")
    }

    #[test]
    fn array_of_strings_is_read_in_order() {
        let claim = json!(["db-oncall", "db-readers"]);
        assert_eq!(
            from_claim(CLAIM, Some(&claim), None),
            ["db-oncall", "db-readers"]
        );
    }

    #[test]
    fn non_string_array_entries_are_ignored() {
        let claim = json!(["db-oncall", 7, null, {"name": "x"}, "db-readers"]);
        assert_eq!(
            from_claim(CLAIM, Some(&claim), None),
            ["db-oncall", "db-readers"]
        );
    }

    #[test]
    fn object_yields_its_keys() {
        let claim = json!({
            "db-oncall": {"2901": "acme.zitadel.cloud"},
            "db-readers": {"2901": "acme.zitadel.cloud", "3377": "partner.example"},
        });
        assert_eq!(
            from_claim(CLAIM, Some(&claim), None),
            ["db-oncall", "db-readers"]
        );
        assert!(from_claim(CLAIM, Some(&json!({})), None).is_empty());
    }

    #[test]
    fn any_other_shape_is_no_groups() {
        for claim in [json!("db-oncall"), json!(7), json!(true), Value::Null] {
            assert!(
                from_claim(CLAIM, Some(&claim), None).is_empty(),
                "{claim:?}"
            );
        }
        assert!(from_claim(CLAIM, None, None).is_empty());
    }

    #[test]
    fn prefix_filters_then_strips_for_both_shapes() {
        let prefix = prefix("dbmcp-");
        let array = json!([
            "dbmcp-oncall",
            "hr-admins",
            "dbmcp-",
            "oncall",
            "dbmcp-readers"
        ]);
        assert_eq!(
            from_claim(CLAIM, Some(&array), Some(&prefix)),
            ["oncall", "readers"]
        );
        let object = json!({"dbmcp-oncall": {}, "billing": {}});
        assert_eq!(from_claim(CLAIM, Some(&object), Some(&prefix)), ["oncall"]);
        assert!(from_claim(CLAIM, Some(&json!(["hr-admins"])), Some(&prefix)).is_empty());
    }
}
