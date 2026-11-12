//! Tracked detached work: the audit fallback writes, stream-sink deliveries,
//! target-side cancels and cache refreshes that must outlive the request that
//! started them but not the process. A bare `tokio::spawn` is dropped when
//! `main` returns, so a fallback audit row written during shutdown was lost;
//! every such spawn goes through [`DetachedTasks`] instead, and `main` drains
//! it with [`DetachedTasks::drain`] after the server stops accepting work.

use std::future::Future;
use std::time::Duration;

use tokio_util::task::TaskTracker;

/// Upper bound `main` waits for detached work at shutdown. Above
/// [`super::AUDIT_WRITE_TIMEOUT`] so a fallback write that started just
/// before shutdown can still reach its own deadline; anything still running
/// past it is left to the reaper (its intent row turns into `abandoned`).
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

/// Cheap to clone: every clone tracks into the same set.
#[derive(Debug, Clone, Default)]
pub struct DetachedTasks(TaskTracker);

/// Detached work was still running when the drain bound elapsed.
#[derive(Debug, thiserror::Error)]
#[error("{pending} detached task(s) still running after {bound:?}")]
pub struct DrainTimedOut {
    pub pending: usize,
    pub bound: Duration,
}

impl DetachedTasks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn `task` on the current runtime, tracked for [`Self::drain`].
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.0.spawn(task);
    }

    /// Close the set and wait up to `bound` for the work in flight. A task
    /// spawned after the close still runs and is still waited for while the
    /// bound lasts.
    pub async fn drain(&self, bound: Duration) -> Result<(), DrainTimedOut> {
        self.0.close();
        tokio::time::timeout(bound, self.0.wait())
            .await
            .map_err(|_| DrainTimedOut {
                pending: self.0.len(),
                bound,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_waits_for_spawned_work() {
        let tasks = DetachedTasks::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = tx.send(());
        });
        tasks
            .drain(Duration::from_secs(5))
            .await
            .expect("drains in bound");
        rx.await
            .expect("task ran to completion before drain returned");
    }

    #[tokio::test]
    async fn drain_reports_work_still_running_at_the_bound() {
        let tasks = DetachedTasks::new();
        tasks.spawn(std::future::pending());
        let err = tasks
            .drain(Duration::from_millis(20))
            .await
            .expect_err("pending task outlives the bound");
        assert_eq!(err.pending, 1);
    }
}
