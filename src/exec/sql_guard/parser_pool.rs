//! The threads libpg_query runs on.
//!
//! It needs a thread's own stack, one that lives on: it sizes its recursion
//! limit from the bounds of the thread (so on a `stacker` stack the limit is
//! arbitrary), and takes one of a process's 1,024 pthread keys for every
//! thread that ever parsed, for good. Hence a few threads for the life of the
//! process, whose panics are caught rather than replaced by new threads.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};

use super::GuardError;
use super::agreement::{Reading, check_agreement};

type Job = Box<dyn FnOnce() + Send>;
type Jobs = Arc<Mutex<mpsc::Receiver<Job>>>;

/// Twice what libpg_query uses at its 2 MiB limit. Untouched pages cost none.
const STACK: usize = 4 << 20;

/// The slowest statement within the bounds takes about 20 ms and 10 MiB.
const THREADS: usize = 4;

/// Waiting statements past the ones being parsed: four callers' request cap.
const QUEUE: usize = 64;

/// For a thread and its answer. Reached only when the queue is not moving.
const WAIT: Duration = Duration::from_secs(5);

/// Parse `sql` with Postgres's grammar and hold it against `reading`.
pub(super) async fn agree(sql: &str, reading: Reading) -> Result<(), GuardError> {
    // The job outlives a caller that stops waiting.
    let sql = sql.to_owned();
    pool()?
        .run(WAIT, move || check_agreement(&sql, &reading))
        .await?
}

#[cfg(any(test, feature = "test-support"))]
pub(super) fn agree_blocking(sql: &str, reading: Reading) -> Result<(), GuardError> {
    let sql = sql.to_owned();
    pool()?.run_blocking(WAIT, move || check_agreement(&sql, &reading))?
}

/// Started by the first statement; a failed start is tried again by the next.
fn pool() -> Result<&'static ParserPool, GuardError> {
    static POOL: OnceLock<ParserPool> = OnceLock::new();
    if let Some(pool) = POOL.get() {
        return Ok(pool);
    }
    match ParserPool::start(THREADS, QUEUE) {
        Ok(pool) => Ok(POOL.get_or_init(|| pool)),
        Err(err) => {
            tracing::error!(%err, "SQL parser threads did not start");
            Err(GuardError::Failed)
        }
    }
}

/// Dropping it ends the threads once they finish what they were given.
#[derive(Debug)]
struct ParserPool(mpsc::Sender<Job>);

impl ParserPool {
    fn start(threads: usize, queue: usize) -> std::io::Result<Self> {
        let (send, receive) = mpsc::channel(queue);
        let jobs = Arc::new(Mutex::new(receive));
        for _ in 0..threads {
            spawn(Arc::clone(&jobs))?;
        }
        Ok(Self(send))
    }

    /// Run `f` on a parser thread, within `wait`.
    async fn run<T: Send + 'static>(
        &self,
        wait: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, GuardError> {
        let (reply, answer) = oneshot::channel();
        self.submit(move || {
            // A caller that stopped waiting needs no answer.
            if !reply.is_closed() {
                let _ = reply.send(f());
            }
        })?;
        match tokio::time::timeout(wait, answer).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_panicked)) => Err(GuardError::Failed),
            Err(_elapsed) => Err(GuardError::Busy),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn run_blocking<T: Send + 'static>(
        &self,
        wait: Duration,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, GuardError> {
        use std::sync::mpsc::{RecvTimeoutError, sync_channel};
        let (reply, answer) = sync_channel(1);
        self.submit(move || {
            let _ = reply.send(f());
        })?;
        answer.recv_timeout(wait).map_err(|err| match err {
            RecvTimeoutError::Timeout => GuardError::Busy,
            RecvTimeoutError::Disconnected => GuardError::Failed,
        })
    }

    fn submit(&self, f: impl FnOnce() + Send + 'static) -> Result<(), GuardError> {
        let job = Box::new(in_callers_span(f));
        self.0.try_send(job).map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => GuardError::Busy,
            mpsc::error::TrySendError::Closed(_) => GuardError::Failed,
        })
    }
}

/// `f`, whose events belong to the calling request wherever it runs.
fn in_callers_span(f: impl FnOnce()) -> impl FnOnce() {
    let span = tracing::Span::current();
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    move || tracing::dispatcher::with_default(&dispatch, || span.in_scope(f))
}

fn spawn(jobs: Jobs) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("sql-parser".to_owned())
        .stack_size(STACK)
        .spawn(move || serve(jobs))
        .map(drop)
}

fn serve(jobs: Jobs) {
    let replace = ReplaceOnUnwind(jobs);
    loop {
        // Held while waiting: the next free thread takes the next job.
        let job = replace.0.blocking_lock().blocking_recv();
        let Some(job) = job else { return };
        // The caller learns from its dropped reply; the thread goes on.
        if catch_unwind(AssertUnwindSafe(job)).is_err() {
            tracing::error!("the SQL guard panicked on a statement");
        }
    }
}

/// A panic's payload can panic as it drops; that ends the thread.
struct ReplaceOnUnwind(Jobs);

impl Drop for ReplaceOnUnwind {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Err(err) = spawn(Arc::clone(&self.0))
        {
            tracing::error!(%err, "a SQL parser thread was not replaced");
        }
    }
}

#[cfg(test)]
mod tests;
