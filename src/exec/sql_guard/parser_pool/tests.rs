use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread::ThreadId;

use super::*;

const SOON: Duration = Duration::from_secs(20);

fn pool(threads: usize, queue: usize) -> ParserPool {
    ParserPool::start(threads, queue).expect("threads start")
}

fn here() -> ThreadId {
    std::thread::current().id()
}

/// Occupies a pool's one thread until the returned sender is dropped.
fn occupy(pool: &ParserPool) -> mpsc::Sender<()> {
    let (release, held) = mpsc::channel::<()>();
    let (started, running) = mpsc::channel();
    pool.submit(move || {
        started.send(()).expect("test waits");
        let _ = held.recv();
    })
    .expect("queued");
    running.recv().expect("runs");
    release
}

#[tokio::test]
async fn work_runs_on_a_parser_thread_and_its_value_comes_back() {
    let pool = pool(2, 4);
    let got = pool
        .run(SOON, || std::thread::current().name().map(str::to_owned))
        .await;
    assert_eq!(got, Ok(Some("sql-parser".to_owned())));
}

#[tokio::test]
async fn a_full_queue_refuses_at_once() {
    let pool = pool(1, 2);
    let release = occupy(&pool);
    for _ in 0..2 {
        pool.submit(|| {}).expect("queued");
    }
    assert_eq!(pool.run(SOON, || 1).await, Err(GuardError::Busy));
    assert_eq!(pool.run_blocking(SOON, || 1), Err(GuardError::Busy));
    drop(release);
    // The queue empties and the pool serves again.
    while pool.0.capacity() < 2 {
        tokio::task::yield_now().await;
    }
    assert_eq!(pool.run(SOON, || 1).await, Ok(1));
}

#[tokio::test]
async fn the_wait_is_bounded_and_an_abandoned_job_never_runs() {
    static RAN: AtomicUsize = AtomicUsize::new(0);
    let pool = pool(1, 4);
    let release = occupy(&pool);
    let brief = Duration::from_millis(20);
    let abandoned = || RAN.fetch_add(1, Ordering::SeqCst);
    assert_eq!(pool.run(brief, abandoned).await, Err(GuardError::Busy));
    assert_eq!(pool.run_blocking(brief, || 1), Err(GuardError::Busy));
    drop(release);
    assert_eq!(pool.run(SOON, || 7).await, Ok(7));
    assert_eq!(RAN.load(Ordering::SeqCst), 0);
}

/// Waiting callers leave the runtime's only worker free for other work.
#[tokio::test(flavor = "current_thread")]
async fn waiting_never_blocks_the_runtime() {
    let pool = pool(1, 4);
    let release = occupy(&pool);
    let waiting = pool.run(SOON, || 1);
    let other_work = async move {
        tokio::task::yield_now().await;
        drop(release);
    };
    let (got, ()) = tokio::join!(waiting, other_work);
    assert_eq!(got, Ok(1));
}

/// A panic refuses its own call and costs no thread (nor its pthread key).
#[tokio::test]
async fn a_panic_refuses_the_call_and_the_thread_goes_on() {
    let pool = pool(1, 4);
    let before = pool.run(SOON, here).await;
    for _ in 0..50 {
        let got: Result<(), _> = pool.run(SOON, || panic!("a bug")).await;
        assert_eq!(got, Err(GuardError::Failed));
        let got: Result<(), _> = pool.run_blocking(SOON, || panic!("a bug"));
        assert_eq!(got, Err(GuardError::Failed));
    }
    assert_eq!(pool.run(SOON, here).await, before);
}

struct PanicsOnDrop;

impl Drop for PanicsOnDrop {
    fn drop(&mut self) {
        panic!("as it drops");
    }
}

#[tokio::test]
async fn a_dead_thread_is_replaced() {
    let pool = pool(1, 4);
    let before = pool.run(SOON, here).await.expect("runs");
    let got: Result<(), _> = pool.run(SOON, || std::panic::panic_any(PanicsOnDrop)).await;
    assert_eq!(got, Err(GuardError::Failed));
    let after = pool.run(SOON, here).await.expect("a new thread runs it");
    assert_ne!(after, before);
}

#[tokio::test]
async fn a_pool_without_threads_refuses() {
    let (send, receive) = tokio::sync::mpsc::channel(1);
    drop(receive);
    let pool = ParserPool(send);
    assert_eq!(pool.run(SOON, || 1).await, Err(GuardError::Failed));
    assert_eq!(pool.run_blocking(SOON, || 1), Err(GuardError::Failed));
}

/// Shutdown: queued work is finished, then the threads end.
#[test]
fn dropping_the_pool_finishes_its_work_and_ends_its_threads() {
    let pool = pool(3, 32);
    let (done, results) = mpsc::channel();
    for i in 0..32 {
        let done = done.clone();
        pool.submit(move || done.send(i).expect("test waits"))
            .expect("queued");
    }
    drop((pool, done));
    let mut finished: Vec<i32> = results.iter().collect();
    finished.sort_unstable();
    assert_eq!(finished, (0..32).collect::<Vec<_>>());
}

#[tokio::test]
async fn more_callers_than_threads_are_all_answered() {
    let pool = Arc::new(pool(2, 64));
    let mut calls = tokio::task::JoinSet::new();
    for i in 0..60 {
        let pool = Arc::clone(&pool);
        calls.spawn(async move { pool.run(SOON, move || i).await });
    }
    let answers = calls.join_all().await;
    assert!(answers.iter().all(Result::is_ok), "{answers:?}");
}

/// libpg_query gives the last thread's limits only to a thread with the
/// stack it asks for; the pool's is twice its 2 MiB.
#[tokio::test]
async fn the_second_parser_refuses_and_admits_through_the_pool() {
    let admitted = super::super::GuardedSql::parse("SELECT 1", super::super::Access::ReadOnly);
    assert!(admitted.await.is_ok());
    let sql = "SELECT x FROM t QUALIFY x = 1";
    let refused = super::super::GuardedSql::parse(sql, super::super::Access::ReadOnly).await;
    assert_eq!(refused, Err(GuardError::ParserDisagreement("syntax")));
}

mod spans {
    use std::sync::{Arc, Mutex};

    use tracing::Instrument;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Lines {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("unpoisoned").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Lines {
        type Writer = Self;

        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[tokio::test]
    async fn events_belong_to_the_calling_request() {
        let lines = Lines::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(lines.clone())
            .with_ansi(false)
            .finish();
        let _default = tracing::subscriber::set_default(subscriber);
        let span = tracing::info_span!("tool_dispatch", request_id = "r-1");
        let pool = pool(1, 1);
        let run = pool.run(SOON, || tracing::info!("from the thread"));
        run.instrument(span).await.expect("runs");
        let logged = String::from_utf8(lines.0.lock().expect("unpoisoned").clone()).expect("text");
        assert!(logged.contains("request_id=\"r-1\""), "{logged}");
        assert!(logged.contains("from the thread"), "{logged}");
    }
}
