use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::fingerprint::Fingerprint;
use super::slot::Slot;
use super::sweep::Slots;
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

fn current(fingerprint: Fingerprint) -> Option<HashMap<AdapterKey, Fingerprint>> {
    Some(HashMap::from([(key(), fingerprint)]))
}

#[test]
fn an_unheld_superseded_slot_is_swept_and_the_live_one_stays() {
    let (old, new) = (Fingerprint::of_test(1), Fingerprint::of_test(2));
    let mut state = Slots::default();
    let slots = vec![Arc::new(Slot::new(old)), Arc::new(Slot::new(new))];
    state.map.insert(key(), slots);
    assert_eq!(state.sweep(SNAPSHOT_LIFETIME), 0, "no reload yet");
    assert_eq!(state.map[&key()].len(), 2);

    state.current = current(new);
    assert_eq!(state.sweep(SNAPSHOT_LIFETIME), 0);
    let slots = &state.map[&key()];
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].fingerprint, new, "the live slot is never retired");
}

#[test]
fn a_held_superseded_slot_waits_for_its_holder_or_the_lifetime() {
    let (old, new) = (Fingerprint::of_test(1), Fingerprint::of_test(2));
    let held = Arc::new(Slot::new(old));
    held.touch();
    let mut state = Slots {
        current: current(new),
        ..Slots::default()
    };
    state.map.insert(key(), vec![Arc::clone(&held)]);
    assert_eq!(state.sweep(SNAPSHOT_LIFETIME), 1, "held and recently asked");
    assert_eq!(state.sweep(Duration::ZERO), 0, "the lifetime ran out");
    assert!(state.map.is_empty(), "an emptied key is removed");
}

#[test]
fn a_removed_database_is_superseded() {
    let state = Slots {
        current: Some(HashMap::new()),
        ..Slots::default()
    };
    assert!(state.is_superseded(&key(), Fingerprint::of_test(1)));
    assert!(!Slots::default().is_superseded(&key(), Fingerprint::of_test(1)));
}

#[tokio::test]
async fn a_straggler_slot_left_unasked_is_swept_without_further_lookups() {
    let registry = AdapterRegistry::with_sweep_interval(Duration::from_millis(10));
    let (old, new) = (Fingerprint::of_test(1), Fingerprint::of_test(2));
    registry.inner.write().await.current = current(new);
    drop(registry.slot(&key(), old).await);
    drop(registry.slot(&key(), new).await);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while registry.inner.read().await.find(&key(), old).is_some() {
        assert!(tokio::time::Instant::now() < deadline, "never swept");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let state = registry.inner.read().await;
    assert!(state.find(&key(), new).is_some(), "the live slot stays");
    assert!(!state.sweeping, "the sweeper stops once nothing is left");
}

#[test]
fn no_request_outlives_a_retiring_snapshot() {
    assert!(SNAPSHOT_LIFETIME > crate::transport::MCP_TIMEOUT);
}
