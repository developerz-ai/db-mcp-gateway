//! [`Slot`]: one lazily-opened adapter.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OnceCell};

use super::super::adapter::DbAdapter;
use super::FAILED_OPEN_TTL;
use super::fingerprint::Fingerprint;

/// One lazily-opened adapter slot.
///
/// The map stores a `OnceCell` rather than a ready adapter so the connect
/// happens *outside* the map lock: callers take the lock only long enough to
/// hand out the slot, then race to initialize it. `OnceCell` gives
/// single-flight semantics — concurrent callers for the same key share one
/// open attempt instead of stampeding the DB — and a failed attempt leaves
/// the cell empty, so a later caller retries once [`FAILED_OPEN_TTL`] has
/// passed (matching the lazy "misconfigured DB errors on use, not at boot"
/// contract).
///
/// `fingerprint` is the config the slot opens from; a caller is only ever
/// served from a slot whose fingerprint is its own.
pub(super) struct Slot {
    pub(super) fingerprint: Fingerprint,
    pub(super) adapter: OnceCell<Arc<dyn DbAdapter>>,
    failed_at: Mutex<Option<Instant>>,
    born: Instant,
    /// Milliseconds after `born` of the latest lookup; atomic so the
    /// read-locked hot path can stamp it.
    last_lookup_ms: AtomicU64,
}

impl Slot {
    pub(super) fn new(fingerprint: Fingerprint) -> Self {
        Self {
            fingerprint,
            adapter: OnceCell::new(),
            failed_at: Mutex::new(None),
            born: Instant::now(),
            last_lookup_ms: AtomicU64::new(0),
        }
    }

    pub(super) async fn recently_failed(&self) -> bool {
        self.failed_at
            .lock()
            .await
            .is_some_and(|at| at.elapsed() < FAILED_OPEN_TTL)
    }

    pub(super) async fn record_failure(&self) {
        *self.failed_at.lock().await = Some(Instant::now());
    }

    pub(super) fn touch(&self) {
        let now = u64::try_from(self.born.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_lookup_ms.store(now, Ordering::Relaxed);
    }

    pub(super) fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_lookup_ms.load(Ordering::Relaxed));
        self.born.elapsed().saturating_sub(last)
    }
}
