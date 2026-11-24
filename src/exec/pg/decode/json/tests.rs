use serde_json::json;

use super::*;
use crate::exec::adapter::MAX_RESULT_BYTES;

#[test]
fn a_cell_that_fits_parses_like_serde_json() {
    let text = br#"{"b": [1, -2, 3.5, "x\ny", null, true], "a": {"k": 18446744073709551615}}"#;
    let budget = ResultBudget::new(10);
    let mut weight = RowWeight::new(&budget);
    let want: Value = serde_json::from_slice(text).expect("valid JSON");
    let JsonCell::Value(parsed) = parse(text, &mut weight) else {
        panic!("a small cell fits");
    };
    // Compared as text: key order is the document's, and `Value`
    // equality would not see a reordering.
    assert_eq!(parsed.to_string(), want.to_string());
    // Charged exactly what `admit` will weigh.
    let nodes = 10 * size_of::<Value>();
    let keys = 3 * (size_of::<String>() + 1);
    assert_eq!(weight.used, nodes + keys + "x\ny".len());
}

#[test]
fn the_parse_stops_at_the_node_that_does_not_fit() {
    // 4 MB on the wire — inside the byte cap — and 64 MB decoded.
    let elements = 2 * MAX_RESULT_BYTES / size_of::<Value>();
    let text = format!("[{}0]", "0,".repeat(elements - 1));
    assert!(text.len() < MAX_RESULT_BYTES);
    let budget = ResultBudget::new(10);
    let mut weight = RowWeight::new(&budget);
    assert_eq!(parse(text.as_bytes(), &mut weight), JsonCell::OverBudget);
    assert!(
        weight.used <= MAX_RESULT_BYTES + size_of::<Value>(),
        "parsed on past the budget: {} bytes",
        weight.used
    );
}

/// `json` (not `jsonb`) stores duplicate keys as written. 4 MB of one
/// repeated key decodes to a single entry, so it is not over budget.
#[test]
fn a_replaced_duplicate_key_is_not_charged() {
    let repeats = MAX_RESULT_BYTES / 16;
    let text = format!(r#"{{{}"k":[2,"last"]}}"#, r#""k":[1,"x"],"#.repeat(repeats));
    assert!(text.len() < MAX_RESULT_BYTES);
    let budget = ResultBudget::new(10);
    let mut weight = RowWeight::new(&budget);
    let JsonCell::Value(parsed) = parse(text.as_bytes(), &mut weight) else {
        panic!("only the last entry is held");
    };
    assert_eq!(parsed, json!({"k": [2, "last"]}));
    let nodes = 4 * size_of::<Value>();
    let key = size_of::<String>() + 1;
    assert_eq!(weight.used, nodes + key + "last".len());
}

/// Parses `text` with the budget and asserts the same tree, in the same
/// key order, as `serde_json`'s own parse; returns the bytes charged.
fn parses_like_serde_json(text: &str) -> usize {
    let budget = ResultBudget::new(10);
    let mut weight = RowWeight::new(&budget);
    let JsonCell::Value(parsed) = parse(text.as_bytes(), &mut weight) else {
        panic!("the final object fits");
    };
    let want: Value = serde_json::from_str(text).expect("valid JSON");
    assert_eq!(parsed.to_string(), want.to_string());
    weight.used
}

/// The replaced value is refunded before its replacement is charged: a
/// first value that nearly fills the budget does not truncate a row
/// whose final value is small.
#[test]
fn a_large_value_replaced_by_a_small_one_fits() {
    let big = "x".repeat(MAX_RESULT_BYTES - 1024);
    let text = format!(r#"{{"a":1,"k":"{big}","b":2,"k":"{}"}}"#, "y".repeat(2048));
    let nodes = 4 * size_of::<Value>();
    let keys = 3 * (size_of::<String>() + 1);
    assert_eq!(parses_like_serde_json(&text), nodes + keys + 2048);
}

/// Two values for one key, each fitting alone but not together.
#[test]
fn two_values_for_one_key_that_each_fit_alone_fit() {
    let value = "v".repeat(MAX_RESULT_BYTES * 3 / 5);
    let text = format!(r#"{{"k":"{value}","z":0,"k":"{value}"}}"#);
    let nodes = 3 * size_of::<Value>();
    let keys = 2 * (size_of::<String>() + 1);
    assert_eq!(parses_like_serde_json(&text), nodes + keys + value.len());
}

#[test]
fn malformed_text_is_invalid_not_over_budget() {
    let budget = ResultBudget::new(10);
    for text in [&b"[1, 2"[..], b"{} trailing", b""] {
        let mut weight = RowWeight::new(&budget);
        assert_eq!(parse(text, &mut weight), JsonCell::Invalid, "{text:?}");
    }
    let mut weight = RowWeight::new(&budget);
    assert_eq!(parse(b"7", &mut weight), JsonCell::Value(json!(7)));
}
