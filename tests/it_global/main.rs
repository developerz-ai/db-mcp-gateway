//! Tests that install a process-wide global exactly once: `json_logging`
//! the tracing subscriber, `metrics_endpoint` the metrics recorder. Kept out
//! of `it_db` so neither global captures (or is captured by) the other suites.

// CLAUDE.md §Conventions: tests may panic; `[lints.clippy]` denies it for shipped code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../common/mod.rs"]
mod common;

mod json_logging;
mod metrics_endpoint;
