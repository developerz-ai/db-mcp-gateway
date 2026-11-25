//! Time the guard takes, measured in a process of its own: a statement that
//! never gets an answer is ended and named instead of holding the run.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use super::*;

/// For one statement, so generous for a loaded machine: the slowest takes
/// about 3 ms optimised, the work budget of its length. What it guards against
/// is time that grows faster than the text.
const DEADLINE: Duration = Duration::from_secs(10);

/// Set for the process that runs the cases.
const RUN_CASES: &str = "DBMCP_TEST_RUN_GUARD_TIMING_CASES";
const CASE: &str = "case ";
const FINISHED: &str = "all cases answered";

const OPENERS: &[&str] = &[
    "(",
    "f(",
    "ARRAY[",
    "CASE ",
    "CASE WHEN ",
    "NOT ",
    "EXISTS(SELECT ",
    "(SELECT ",
    "CAST(",
    "CAST(CASE ",
    "IF(",
    "current_time(",
    "INTERVAL ",
    "ROW(",
    "VALUES(",
    "a IN (",
    "a[",
    "a.",
    "f(a=>",
    "TRIM(",
    "LATERAL (",
    "SELECT * FROM (",
    "NOT (a).",
    "CAST(a.",
    "(a).",
    "f(a.",
    "CASE a.",
    "a.NOT ",
    "EXTRACT(",
    "POSITION(a IN ",
    "XMLELEMENT(",
    "(a).b(",
    "ARRAY[a.",
    "OVERLAY(",
    "WITH a AS (",
    "((SELECT 1) UNION ",
];

/// Runs itself again as the process that measures, so the one filter that
/// names this test selects exactly its cases.
#[test]
fn openers_repeated_or_alternating_answer_in_bounded_time() {
    if std::env::var_os(RUN_CASES).is_some() {
        return run_cases();
    }
    let (_, module) = module_path!().split_once("::").expect("crate::module");
    let test = format!("{module}::openers_repeated_or_alternating_answer_in_bounded_time");
    let mut child = Command::new(std::env::current_exe().expect("the test binary's path"))
        .args(["--exact", &test, "--nocapture"])
        .env(RUN_CASES, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the test binary starts");
    let lines = lines_of(&mut child);
    let outcome = follow(&lines);
    if outcome.is_err() {
        // Already gone is fine: it is reaped below either way.
        let _ = child.kill();
    }
    let status = child.wait().expect("the process is reaped");
    match outcome {
        Err(stalled) => panic!("no answer within {DEADLINE:?}: {stalled}"),
        Ok(printed) => assert!(
            status.success() && printed.last().is_some_and(|line| line == FINISHED),
            "{status}, after:\n{}",
            printed.join("\n")
        ),
    }
}

/// Announces each case on stderr before it runs.
fn run_cases() {
    let pairs = OPENERS
        .iter()
        .flat_map(|a| OPENERS.iter().map(move |b| format!("{a}{b}")));
    for unit in pairs {
        for n in [12, 24, 48] {
            eprintln!("{CASE}{unit:?} x {n}");
            let sql = format!("SELECT {}1", unit.repeat(n));
            let _ = on_worker_stack(move || is_read_only(&sql));
        }
    }
    eprintln!("{FINISHED}");
}

fn lines_of(child: &mut Child) -> Receiver<String> {
    let stderr = child.stderr.take().expect("stderr is piped");
    let (send, lines) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    lines
}

/// The lines from the last announced case on, once the process closes its
/// stderr; the same as an error when none arrives within [`DEADLINE`].
fn follow(lines: &Receiver<String>) -> Result<Vec<String>, String> {
    let mut printed = Vec::new();
    loop {
        match lines.recv_timeout(DEADLINE) {
            Ok(line) => {
                if line.starts_with(CASE) {
                    printed.clear();
                }
                printed.push(line);
            }
            Err(RecvTimeoutError::Timeout) => return Err(printed.join("\n")),
            Err(RecvTimeoutError::Disconnected) => return Ok(printed),
        }
    }
}
