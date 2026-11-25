//! A long statement leaves its async worker to the other tasks on it.

use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use super::*;
use crate::exec::sql_guard::bounds::off_the_worker;

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
