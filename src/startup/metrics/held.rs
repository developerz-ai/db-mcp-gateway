//! Gauges set on a rare event (boot, a reload, an hourly prune) and re-set on
//! a timer. The recorder drops a gauge untouched for its idle timeout, so a
//! value set once would vanish from the scrape an hour later while still
//! true (plan 101 O3).

use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Well inside the recorder's idle timeout, so a held gauge never lapses.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(60);

type Labels = Vec<(&'static str, String)>;

#[derive(Debug)]
struct Entry {
    name: &'static str,
    labels: Labels,
    value: f64,
}

/// The held values. One process-wide set ([`held`]); tests build their own.
#[derive(Debug, Default)]
pub(crate) struct HeldGauges {
    entries: Mutex<Vec<Entry>>,
}

impl HeldGauges {
    /// Set the gauge now and keep re-setting it to `value`.
    pub(crate) fn set(&self, name: &'static str, labels: Labels, value: f64) {
        emit(name, &labels, value);
        let mut entries = self.lock();
        match entries
            .iter_mut()
            .find(|e| e.name == name && e.labels == labels)
        {
            Some(entry) => entry.value = value,
            None => entries.push(Entry {
                name,
                labels,
                value,
            }),
        }
    }

    /// An info-style gauge (`1` on the current label set): the previous label
    /// set drops to `0` and stops being held, so it leaves the scrape after
    /// the idle timeout instead of reading as current.
    pub(crate) fn set_info(&self, name: &'static str, labels: Labels) {
        let previous: Vec<Labels> = {
            let mut entries = self.lock();
            let (old, kept): (Vec<Entry>, Vec<Entry>) = std::mem::take(&mut *entries)
                .into_iter()
                .partition(|e| e.name == name && e.labels != labels);
            *entries = kept;
            old.into_iter().map(|e| e.labels).collect()
        };
        for labels in previous {
            emit(name, &labels, 0.0);
        }
        self.set(name, labels, 1.0);
    }

    /// Re-set every held gauge to its value.
    pub(crate) fn refresh(&self) {
        for entry in self.lock().iter() {
            emit(entry.name, &entry.labels, entry.value);
        }
    }

    /// The lock is never held across an await or a panic-prone call, so a
    /// poisoned lock still holds consistent entries.
    fn lock(&self) -> MutexGuard<'_, Vec<Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn emit(name: &'static str, labels: &Labels, value: f64) {
    let labels: Vec<metrics::Label> = labels
        .iter()
        .map(|(key, value)| metrics::Label::new(*key, value.clone()))
        .collect();
    metrics::gauge!(name, labels).set(value);
}

/// The process-wide held set.
pub(crate) fn held() -> &'static HeldGauges {
    static HELD: LazyLock<HeldGauges> = LazyLock::new(HeldGauges::default);
    &HELD
}

/// Re-set `gauges` every `every` until `shutdown`.
pub(crate) async fn run_refresher(
    gauges: &HeldGauges,
    every: Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(every);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => gauges.refresh(),
        }
    }
}

/// Unix seconds now, as a gauge value.
pub(crate) fn unix_now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or_default()
}
