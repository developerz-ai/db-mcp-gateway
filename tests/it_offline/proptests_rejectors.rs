//! Property tests for the read-only rejectors, against their public API:
//! whatever an agent sends, the Redis rewriter never lets a SCAN-family
//! `COUNT` past [`MAX_SCAN_COUNT`] and never accepts a write, and the Mongo
//! rejector finds a denied operator at any depth of an allowed command.

use db_mcp_gateway::exec::mongo::rejector as mongo;
use db_mcp_gateway::exec::redis::rejector::{self as redis, MAX_SCAN_COUNT};
use proptest::prelude::*;
use serde_json::{Map, Value, json};

/// Every `COUNT` value in an accepted command's args.
fn counts(args: &[String]) -> Vec<u64> {
    args.windows(2)
        .filter(|pair| pair[0].eq_ignore_ascii_case("COUNT"))
        .map(|pair| pair[1].parse().expect("an accepted COUNT is numeric"))
        .collect()
}

/// A COUNT value as an agent might send it: huge, zero, negative, junk.
fn count_value() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<u64>().prop_map(|n| n.to_string()),
        any::<i64>().prop_map(|n| n.to_string()),
        "[0-9]{1,30}",
        ".{0,8}",
    ]
}

fn option() -> impl Strategy<Value = Vec<String>> {
    prop_oneof![
        count_value().prop_map(|n| vec!["COUNT".to_string(), n]),
        count_value().prop_map(|n| vec!["count".to_string(), n]),
        "[a-z*]{0,6}".prop_map(|p| vec!["MATCH".to_string(), p]),
    ]
}

proptest! {
    #[test]
    fn redis_scan_count_never_exceeds_the_cap(
        command in prop::sample::select(vec!["SCAN", "scan", "SSCAN", "HSCAN", "ZSCAN"]),
        options in prop::collection::vec(option(), 0..4),
    ) {
        let mut argv = vec![command.to_string()];
        if !command.eq_ignore_ascii_case("SCAN") {
            argv.push("gw:key".to_string());
        }
        argv.push("0".to_string());
        argv.extend(options.into_iter().flatten());
        let json = serde_json::to_string(&argv).unwrap();
        if let Ok(accepted) = redis::validate_command(&json) {
            for count in counts(&accepted.args) {
                prop_assert!(count >= 1 && count <= u64::from(MAX_SCAN_COUNT), "{json} -> {count}");
            }
        }
    }

    /// No casing of a write or admin command gets through, whatever follows.
    #[test]
    fn redis_never_accepts_a_write(
        command in prop::sample::select(vec![
            "SET", "DEL", "FLUSHDB", "FLUSHALL", "EVAL", "CONFIG", "KEYS", "HSET",
            "LPUSH", "EXPIRE", "RENAME", "SCRIPT", "MODULE", "SHUTDOWN", "MIGRATE",
        ]),
        flips in prop::collection::vec(any::<bool>(), 16),
        args in prop::collection::vec("[ -~]{0,8}", 0..4),
    ) {
        let cased: String = command
            .chars()
            .zip(flips.iter().cycle())
            .map(|(c, lower)| if *lower { c.to_ascii_lowercase() } else { c })
            .collect();
        let mut argv = vec![cased];
        argv.extend(args);
        let json = serde_json::to_string(&argv).unwrap();
        prop_assert!(redis::validate_command(&json).is_err(), "{json} was accepted");
    }

    /// Arbitrary bytes never panic the parser.
    #[test]
    fn redis_and_mongo_survive_arbitrary_input(input in ".{0,64}") {
        let _ = redis::validate_command(&input);
        let _ = mongo::validate_command(&input);
    }
}

const DENIED: &[&str] = &["$out", "$merge", "$function", "$where", "$accumulator"];

/// A random JSON tree with no `$`-operator keys of its own.
fn tree() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<i64>().prop_map(Value::from),
        "[a-z]{0,6}".prop_map(Value::from),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-z]{1,6}", inner, 0..4)
                .prop_map(|map| Value::Object(map.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// Put `{operator: 1}` somewhere inside `value`, steering by `path`.
fn plant(value: &mut Value, path: &[usize], operator: &str) {
    let child = match value {
        Value::Array(items) if !items.is_empty() => {
            let at = path.first().copied().unwrap_or(0) % items.len();
            items.get_mut(at)
        }
        Value::Object(map) if !map.is_empty() => {
            let at = path.first().copied().unwrap_or(0) % map.len();
            map.values_mut().nth(at)
        }
        _ => None,
    };
    match (child, path.split_first()) {
        (Some(child), Some((_, rest))) if !rest.is_empty() => plant(child, rest, operator),
        _ => *value = json!([value.take(), { operator: 1 }]),
    }
}

proptest! {
    #[test]
    fn mongo_finds_a_denied_operator_at_any_depth(
        mut stage in tree(),
        path in prop::collection::vec(any::<usize>(), 0..6),
        operator in prop::sample::select(DENIED.to_vec()),
    ) {
        plant(&mut stage, &path, operator);
        let command = json!({"aggregate": "items", "pipeline": [{"$match": stage}], "cursor": {}});
        let text = command.to_string();
        prop_assert!(
            matches!(mongo::validate_command(&text), Err(mongo::RejectReason::DisallowedOperator(_))),
            "{text} was not refused for {operator}"
        );
    }

    /// The same trees without a planted operator are not refused for one.
    #[test]
    fn mongo_clean_trees_are_not_refused_for_an_operator(stage in tree()) {
        let command = json!({"aggregate": "items", "pipeline": [{"$match": stage}], "cursor": {}});
        let verdict = mongo::validate_command(&command.to_string());
        prop_assert!(
            !matches!(verdict, Err(mongo::RejectReason::DisallowedOperator(_))),
            "{command}: {verdict:?}"
        );
    }
}

/// The property above is not vacuous: an oversized COUNT is accepted and
/// clamped, not refused.
#[test]
fn redis_an_oversized_count_is_clamped_not_refused() {
    let accepted = redis::validate_command(r#"["SCAN","0","COUNT","999999999"]"#).unwrap();
    assert_eq!(counts(&accepted.args), vec![u64::from(MAX_SCAN_COUNT)]);
}
