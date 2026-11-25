//! A long statement leaves its async worker to the other tasks on it, in turn
//! with the other long statements; one whose caller goes away while it waits
//! is never parsed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use super::*;
use crate::exec::sql_guard::bounds::{off_the_worker, turns};
use crate::exec::sql_guard::hold::{Hold, hold};

const SOON: Duration = Duration::from_secs(10);

/// Whether the runtime's one worker runs another task while `off_the_worker`
/// holds a statement of `bytes` bytes.
async fn another_task_runs_meanwhile(bytes: usize, wait: Duration) -> bool {
    let (ran, seen) = channel();
    let guarding = tokio::spawn(async move {
        tokio::spawn(async move { ran.send(()) });
        off_the_worker(bytes, move || seen.recv_timeout(wait)).await
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

fn long_statement(marker: &str) -> String {
    to_length(&format!("SELECT {marker}"), "+a", MAX_SQL_BYTES)
}

async fn guarded(sql: String) -> Result<Access, GuardError> {
    GuardedSql::parse_async(&sql, Access::ReadOnly)
        .await
        .map(|guarded| guarded.required_access())
}

#[tokio::test]
async fn a_long_statement_is_guarded_where_there_is_no_other_worker() {
    assert_eq!(guarded(long_statement("a")).await, Ok(Access::ReadOnly));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_long_statement_is_guarded_on_a_blocking_thread() {
    let sql = long_statement("a");
    let guarded = tokio::task::spawn_blocking(move || is_read_only(&sql));
    assert_eq!(guarded.await.expect("returns"), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn as_many_long_statements_are_guarded_at_once_as_there_are_turns() {
    static NOW: AtomicUsize = AtomicUsize::new(0);
    static MOST: AtomicUsize = AtomicUsize::new(0);
    let turns = turns().available_permits();
    let tasks: Vec<_> = (0..turns * 3)
        .map(|_| {
            tokio::spawn(off_the_worker(MAX_SQL_BYTES, || {
                let now = NOW.fetch_add(1, Ordering::SeqCst) + 1;
                MOST.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                NOW.fetch_sub(1, Ordering::SeqCst);
            }))
        })
        .collect();
    for task in tasks {
        task.await.expect("returns");
    }
    let most = MOST.load(Ordering::SeqCst);
    assert!(most <= turns, "{most} at once, {turns} turns");
    assert!(most > 1 || turns == 1, "one at a time");
}

/// Every turn taken by a statement held in its parse.
async fn every_turn_held() -> (
    Vec<Hold>,
    Vec<tokio::task::JoinHandle<Result<Access, GuardError>>>,
) {
    let markers: Vec<_> = (0..turns().available_permits())
        .map(|i| format!("held_{i}_{}", uuid::Uuid::new_v4().simple()))
        .collect();
    let holds: Vec<_> = markers.iter().map(|marker| hold(marker)).collect();
    let tasks = markers
        .iter()
        .map(|marker| tokio::spawn(guarded(long_statement(marker))))
        .collect();
    let holds = tokio::task::spawn_blocking(move || {
        for hold in &holds {
            hold.entered.recv_timeout(SOON).expect("held");
        }
        holds
    })
    .await
    .expect("waits");
    (holds, tasks)
}

/// The test holds every turn, so it runs alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_statement_whose_caller_leaves_while_it_waits_is_never_parsed() {
    let (holds, tasks) = every_turn_held().await;
    assert_eq!(turns().available_permits(), 0);

    let marker = format!("left_{}", uuid::Uuid::new_v4().simple());
    let left = hold(&marker);
    let waiting =
        tokio::time::timeout(Duration::from_millis(200), guarded(long_statement(&marker)));
    assert!(waiting.await.is_err(), "it waits for a turn");

    drop(holds);
    for task in tasks {
        assert_eq!(task.await.expect("returns"), Ok(Access::ReadOnly));
    }
    let never =
        tokio::task::spawn_blocking(move || left.entered.recv_timeout(Duration::from_secs(1)));
    assert_eq!(never.await.expect("waits"), Err(RecvTimeoutError::Timeout));
    // Its place in the queue is free again.
    let next = tokio::time::timeout(SOON, guarded(long_statement("next")));
    assert_eq!(next.await.expect("a turn"), Ok(Access::ReadOnly));
}
