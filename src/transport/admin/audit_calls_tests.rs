//! Unit tests for the audit export's batching.

use super::*;

fn batch(rows: i64, page_rows: i64) -> Batch {
    let mut batch = Batch {
        page_rows,
        ..Batch::default()
    };
    for _ in 0..rows {
        batch.push(&json!({ "id": 1 }), (Utc::now(), uuid::Uuid::new_v4()));
    }
    batch
}

#[test]
fn a_batch_cut_by_bytes_or_a_full_page_has_more() {
    assert!(batch(3, 200).more(200), "the byte bound cut the page");
    assert!(batch(200, 200).more(200), "a full page");
    assert!(!batch(150, 150).more(200), "the query ran out of rows");
    assert!(!batch(0, 0).more(200), "nothing left");
    assert_eq!(batch(3, 200).text.lines().count(), 3);
}
