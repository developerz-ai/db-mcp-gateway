//! Unit tests for the audit export's batching.

use super::*;

#[test]
fn a_batch_stops_at_its_byte_bound() {
    let line = json!({ "sql": "x".repeat(64 * 1024), "params": "y".repeat(64 * 1024) });
    let mut batch = Batch::default();
    let mut pushed = 0;
    while !batch.push(&line, (Utc::now(), uuid::Uuid::new_v4())) {
        pushed += 1;
        assert!(pushed < 200, "never full");
    }
    assert!(batch.full && batch.rows < 10, "{} rows", batch.rows);
    assert!(batch.text.len() < BATCH_BYTES + 140 * 1024);
    assert_eq!(batch.text.lines().count(), batch.rows);
}
