//! Unit tests for result sizing.

use super::*;
use serde_json::json;

fn cap(n: u32) -> Option<NonZeroU32> {
    NonZeroU32::new(n)
}

fn max_bytes(n: u32) -> Option<MaxBytes> {
    Some(MaxBytes::try_from(n).expect("a valid max_bytes"))
}

fn rows(n: i64) -> Vec<Vec<Value>> {
    (0..n).map(|i| vec![json!(i)]).collect()
}

const ASKED_10: RowLimit = RowLimit {
    effective: 10,
    asked: 10,
};

#[test]
fn untruncated_result_has_no_cause_or_hint() {
    let (kept, sizing) = shape(
        rows(3),
        false,
        ASKED_10,
        ByteCaps::default(),
        ServerKind::Postgres,
    );
    assert_eq!(kept.len(), 3);
    let wire = serde_json::to_value(&sizing).unwrap();
    assert_eq!(wire, json!({"truncated": false, "row_limit": 10}));
}

#[test]
fn row_cap_is_the_callers_limit_unless_the_grant_clipped_it() {
    let (_, sizing) = shape(
        rows(10),
        true,
        ASKED_10,
        ByteCaps::default(),
        ServerKind::Postgres,
    );
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::Limit));
    assert!(sizing.hint.as_deref().unwrap().contains("WHERE key >"));

    let clipped = RowLimit {
        effective: 10,
        asked: 1000,
    };
    let (_, sizing) = shape(
        rows(10),
        true,
        clipped,
        ByteCaps::default(),
        ServerKind::Mongo,
    );
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::GrantRowLimit));
    assert!(sizing.hint.as_deref().unwrap().contains("$gt"));
}

/// The adapter stopped short of the row limit: its byte budget cut first.
#[test]
fn adapter_truncation_short_of_the_row_limit_is_the_byte_cap() {
    let (_, sizing) = shape(
        rows(4),
        true,
        ASKED_10,
        ByteCaps::default(),
        ServerKind::Redis,
    );
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::ByteCap));
    assert!(sizing.truncated);
}

#[test]
fn max_bytes_keeps_the_leading_rows_whose_json_fits() {
    // `[[0],[1],[2]]` is 13 bytes; `[[0],[1]]` 9.
    let caps = ByteCaps {
        max_bytes: max_bytes(12),
        ..ByteCaps::default()
    };
    let (kept, sizing) = shape(rows(3), false, ASKED_10, caps, ServerKind::Postgres);
    assert_eq!(kept, rows(2));
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::ByteCap));
    assert!(sizing.truncated);

    let exact = ByteCaps {
        max_bytes: max_bytes(13),
        ..ByteCaps::default()
    };
    let (kept, sizing) = shape(rows(3), false, ASKED_10, exact, ServerKind::Postgres);
    assert_eq!(kept.len(), 3);
    assert!(!sizing.truncated);
}

#[test]
fn an_oversized_cell_is_replaced_by_the_marker() {
    let big = "é".repeat(20); // 40 bytes of UTF-8, 42 as JSON
    let caps = ByteCaps {
        max_cell_bytes: cap(5),
        ..ByteCaps::default()
    };
    let input = vec![
        vec![json!(1), json!(big)],
        vec![json!({"k": [1, 2, 3]}), json!("ok")],
    ];
    let (kept, sizing) = shape(input, false, ASKED_10, caps, ServerKind::Postgres);
    assert_eq!(kept[0][0], json!(1));
    // The preview stops on a char boundary at or below the cap.
    assert_eq!(
        kept[0][1],
        json!({CELL_MARKER: {"bytes": 42, "preview": "éé"}})
    );
    assert_eq!(
        kept[1][0],
        json!({CELL_MARKER: {"bytes": 13, "preview": "{\"k\":"}})
    );
    assert_eq!(kept[1][1], json!("ok"));
    assert_eq!(sizing.cells_truncated, 2);
    assert!(!sizing.truncated, "capping a cell drops no row");
}

/// Rows past the byte cut are dropped before their cells are shaped: only
/// the returned rows' cells become markers, and only they are counted.
#[test]
fn rows_past_the_byte_cap_are_never_shaped() {
    let wide = || (0..50).map(|_| json!("x".repeat(64))).collect::<Vec<_>>();
    let caps = ByteCaps {
        max_bytes: max_bytes(4096),
        max_cell_bytes: cap(1),
    };
    let (kept, sizing) = shape(
        (0..1000).map(|_| wide()).collect(),
        false,
        RowLimit {
            effective: 1000,
            asked: 1000,
        },
        caps,
        ServerKind::Postgres,
    );
    assert!(!kept.is_empty() && kept.len() < 1000);
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::ByteCap));
    assert_eq!(sizing.cells_truncated, kept.len() * 50);
    assert!(json_len(&kept) <= 4096);
}

/// Three rows of 12 MiB each: 36 MiB of JSON, past the 32 MiB ceiling.
fn oversized_rows() -> Vec<Vec<Value>> {
    let cell = "x".repeat(12 * 1024 * 1024);
    (0..3).map(|_| vec![json!(cell)]).collect()
}

#[test]
fn caller_max_bytes_is_clamped_to_the_gateway_budget() {
    let caps = ByteCaps {
        max_bytes: max_bytes(u32::MAX),
        ..ByteCaps::default()
    };
    let (kept, sizing) = shape(
        oversized_rows(),
        false,
        ASKED_10,
        caps,
        ServerKind::Postgres,
    );
    assert_eq!(kept.len(), 2, "the third row crosses 32 MiB");
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::ByteCap));
}

/// Shaping can grow a result (a marker outweighs a short cell, escaping a
/// raw byte): the ceiling holds without a caller `max_bytes` too.
#[test]
fn the_gateway_ceiling_holds_without_a_caller_max_bytes() {
    let (kept, sizing) = shape(
        oversized_rows(),
        false,
        ASKED_10,
        ByteCaps::default(),
        ServerKind::Postgres,
    );
    assert_eq!(kept.len(), 2);
    assert!(sizing.truncated);
    assert_eq!(sizing.truncated_by, Some(TruncatedBy::ByteCap));
}

/// `[]` is two bytes: a smaller cap could never be met.
#[test]
fn max_bytes_below_an_empty_rows_array_is_refused() {
    assert!(MaxBytes::try_from(0).is_err());
    assert!(MaxBytes::try_from(1).is_err());
    assert!(MaxBytes::try_from(2).is_ok());
    let err = serde_json::from_value::<MaxBytes>(json!(1)).expect_err("too small");
    assert!(
        err.to_string().contains("`max_bytes` must be at least 2"),
        "{err}"
    );
}

#[test]
fn json_len_matches_the_serialised_text() {
    let value = json!({"a": ["x\"y", 1.5, null], "b": "é"});
    assert_eq!(json_len(&value), value.to_string().len());
}
