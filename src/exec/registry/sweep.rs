//! [`Slots`]: the registry's map, and the retirement of slots a config reload
//! superseded.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use super::AdapterKey;
use super::fingerprint::Fingerprint;
use super::slot::Slot;

/// Everything behind the registry's lock.
#[derive(Default)]
pub(super) struct Slots {
    /// One slot per config fingerprint seen for the key. Normally one; a
    /// reload briefly leaves the pre-reload snapshot's slot beside the new
    /// one.
    pub(super) map: HashMap<AdapterKey, Vec<Arc<Slot>>>,
    /// The fingerprint of every database in the current config; `None` until
    /// the first reload, before which no slot can be superseded.
    pub(super) current: Option<HashMap<AdapterKey, Fingerprint>>,
    /// Whether a sweeper task is running.
    pub(super) sweeping: bool,
}

impl Slots {
    pub(super) fn find(&self, key: &AdapterKey, fingerprint: Fingerprint) -> Option<Arc<Slot>> {
        self.map
            .get(key)?
            .iter()
            .find(|slot| slot.fingerprint == fingerprint)
            .map(Arc::clone)
    }

    /// Whether a slot for `key` opened from `fingerprint` belongs to a config
    /// other than the current one — changed settings, or a removed database.
    pub(super) fn is_superseded(&self, key: &AdapterKey, fingerprint: Fingerprint) -> bool {
        self.current
            .as_ref()
            .is_some_and(|current| current.get(key) != Some(&fingerprint))
    }

    /// Drop every superseded slot no request holds, or no lookup reached for
    /// `lifetime`. A caller still holding a dropped slot's adapter finishes
    /// on it; its pools close when the last of them lets go. Returns how
    /// many superseded slots are left.
    pub(super) fn sweep(&mut self, lifetime: Duration) -> usize {
        let Some(current) = &self.current else {
            return 0;
        };
        let mut left = 0;
        self.map.retain(|key, slots| {
            slots.retain(|slot| {
                if current.get(key) == Some(&slot.fingerprint) {
                    return true;
                }
                let keep = in_use(slot) && slot.idle_for() < lifetime;
                left += usize::from(keep);
                keep
            });
            !slots.is_empty()
        });
        left
    }
}

/// Whether a lookup or a request holds the slot or its adapter beyond the
/// map's own reference. Lookups clone under the lock the sweep holds, so the
/// count cannot rise while it reads.
fn in_use(slot: &Arc<Slot>) -> bool {
    Arc::strong_count(slot) > 1
        || slot
            .adapter
            .get()
            .is_some_and(|adapter| Arc::strong_count(adapter) > 1)
}
