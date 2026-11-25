//! A long statement leaves its async worker to the other tasks on it.

use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::exec::sql_guard::bounds::{off_the_worker, turns};

const SOON: Duration = Duration::from_secs(10);

/// Whether the runtime's one worker runs another task while `off_the_worker`
/// holds a statement of `bytes` bytes.
async fn another_task_runs_meanwhile(bytes: usize, wait: Duration) -> bool {
    let (ran, seen) = channel();
    let guarding = tokio::spawn(async move {
        tokio::spawn(async move { ran.send(()) });
        off_the_worker(bytes, || seen.recv_timeout(wait))
    });
    match guarding.await.expect("the guard returns") {
        Ok(()) => true,
        Err(RecvTimeoutError::Timeout) => false,
        Err(RecvTimeoutError::Disconnected) => panic!("the other task was dropped"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn other_tasks_run_while_a_long_statement_is_guarded() {
    assert!(another_task_runs_meanwhile(MAX_SQL_BYTES, SOON).await);
    let short = Duration::from_millis(50);
    assert!(!another_task_runs_meanwhile(100, short).await);
}

#[tokio::test]
async fn a_long_statement_is_guarded_where_there_is_no_other_worker() {
    assert_eq!(
        is_read_only(&to_length("SELECT a", "+a", MAX_SQL_BYTES)),
        Ok(())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_long_statement_is_guarded_on_a_blocking_thread() {
    let guarded =
        tokio::task::spawn_blocking(|| is_read_only(&to_length("SELECT a", "+a", MAX_SQL_BYTES)));
    assert_eq!(guarded.await.expect("returns"), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn as_many_long_statements_are_guarded_at_once_as_there_are_turns() {
    static NOW: AtomicUsize = AtomicUsize::new(0);
    static MOST: AtomicUsize = AtomicUsize::new(0);
    let turns = turns().available_permits();
    let tasks: Vec<_> = (0..turns * 3)
        .map(|_| {
            tokio::spawn(async {
                off_the_worker(MAX_SQL_BYTES, || {
                    let now = NOW.fetch_add(1, Ordering::SeqCst) + 1;
                    MOST.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(20));
                    NOW.fetch_sub(1, Ordering::SeqCst);
                })
            })
        })
        .collect();
    for task in tasks {
        task.await.expect("returns");
    }
    let most = MOST.load(Ordering::SeqCst);
    assert!(most <= turns, "{most} at once, {turns} turns");
    assert!(most > 1 || turns == 1, "one at a time");
}
