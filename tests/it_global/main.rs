//! Tests that install a process-wide global exactly once: `json_logging`
//! the tracing subscriber, `metrics_endpoint` the metrics recorder. Kept out
//! of `it_db` so neither global captures (or is captured by) the other suites.

#[path = "../common/mod.rs"]
mod common;

mod json_logging;
mod metrics_endpoint;
