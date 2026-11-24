use std::sync::Arc;
use std::time::Duration;

use super::fingerprint::Fingerprint;
use super::slot::{self, Slot};
use super::{AdapterKey, AdapterRegistry, SNAPSHOT_LIFETIME};

fn key() -> AdapterKey {
    ("s".to_string(), "d".to_string())
}

#[tokio::test]
async fn old_and_new_snapshots_keep_their_own_slot() {
    let registry = AdapterRegistry::new();
    let (old, new) = (Fingerprint::of_test(1), Fingerprint::of_test(2));
    let old_slot = registry.slot(&key(), old).await;
    let new_slot = registry.slot(&key(), new).await;
    for _ in 0..3 {
        assert!(Arc::ptr_eq(&old_slot, &registry.slot(&key(), old).await));
        assert!(Arc::ptr_eq(&new_slot, &registry.slot(&key(), new).await));
    }
}

#[tokio::test]
async fn evict_drops_every_snapshot_of_the_key() {
    let registry = AdapterRegistry::new();
    let (old, new) = (Fingerprint::of_test(1), Fingerprint::of_test(2));
    let old_slot = registry.slot(&key(), old).await;
    let new_slot = registry.slot(&key(), new).await;
    registry.evict("s", "d").await;
    assert!(!Arc::ptr_eq(&old_slot, &registry.slot(&key(), old).await));
    assert!(!Arc::ptr_eq(&new_slot, &registry.slot(&key(), new).await));
}

#[tokio::test]
async fn an_unasked_sibling_retires_and_the_live_slot_stays() {
    let (old, new) = (Fingerprint::of_test(1), Fingerprint::of_test(2));
    let mut slots = vec![Arc::new(Slot::new(old)), Arc::new(Slot::new(new))];
    for slot in &slots {
        slot.touch();
    }
    assert!(!slot::has_retired(&slots, new, SNAPSHOT_LIFETIME));
    slot::retire(&mut slots, new, SNAPSHOT_LIFETIME);
    assert_eq!(slots.len(), 2, "a sibling asked for recently is kept");

    tokio::time::sleep(Duration::from_millis(5)).await;
    let lifetime = Duration::from_millis(1);
    assert!(slot::has_retired(&slots, new, lifetime));
    slot::retire(&mut slots, new, lifetime);
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].fingerprint, new, "the live slot is never retired");
}

#[test]
fn no_request_outlives_a_retiring_snapshot() {
    assert!(SNAPSHOT_LIFETIME > crate::transport::MCP_TIMEOUT);
}
