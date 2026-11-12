//! The global JSON-per-line stdout subscriber and its dropped-line counter.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing_appender::non_blocking::{ErrorCounter, WorkerGuard};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;

/// Used when `RUST_LOG` is unset or empty. Before this default the filter fell
/// back to ERROR, so an unconfigured deploy shipped no operational logs at all.
/// `sqlx::query` stays at WARN: at INFO it logs every statement, agent SQL
/// included, into the operational stream.
const DEFAULT_FILTER: &str = "info,sqlx::query=warn";
/// Spec 07 §Stream: the stdout audit sink is an export, not a log level choice.
/// Pinned on top of any `RUST_LOG` so `RUST_LOG=warn` cannot silence it.
const AUDIT_STREAM_DIRECTIVE: &str = "audit_stream=info";
const DROPPED_LINES_SAMPLE: Duration = Duration::from_secs(15);

/// Install the global JSON-per-line stdout subscriber for Loki (see
/// docs/deployment/logging.md for the field contract). `flatten_event` hoists
/// event fields to the top level so Alloy needs no nested-field stage.
/// `with_target(true)` keeps `target`, which `audit_stream` events set
/// explicitly so operators route the SIEM export separately.
///
/// Writes go through `tracing_appender::non_blocking` so a slow stdout consumer
/// never blocks the request path; when its queue is full lines are dropped and
/// counted — export that count with [`spawn_dropped_lines_exporter`]. The
/// returned guard MUST outlive `run` so the queue drains on shutdown.
pub(crate) fn init_logging() -> anyhow::Result<(WorkerGuard, ErrorCounter)> {
    let (writer, guard) = tracing_appender::non_blocking(std::io::stdout());
    let dropped = writer.error_counter();
    tracing_subscriber::fmt()
        .with_env_filter(env_filter(std::env::var("RUST_LOG").ok().as_deref())?)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .with_writer(writer)
        .init();
    Ok((guard, dropped))
}

/// Invalid `RUST_LOG` directives are skipped, as before — a typo in a log
/// level must not take the gateway down.
fn env_filter(rust_log: Option<&str>) -> anyhow::Result<EnvFilter> {
    let base = match rust_log.map(str::trim) {
        None | Some("") => EnvFilter::new(DEFAULT_FILTER),
        Some(directives) => EnvFilter::builder().parse_lossy(directives),
    };
    let audit: Directive = AUDIT_STREAM_DIRECTIVE.parse()?;
    Ok(base.add_directive(audit))
}

/// Publish the non-blocking writer's dropped-line count as
/// `log_lines_dropped_total` until `shutdown`.
pub(crate) fn spawn_dropped_lines_exporter(dropped: ErrorCounter, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DROPPED_LINES_SAMPLE);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let total = u64::try_from(dropped.dropped_lines()).unwrap_or(u64::MAX);
                    metrics::counter!("log_lines_dropped_total").absolute(total);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::env_filter;

    /// Render what `filter` lets through for one audit-stream and one
    /// operational INFO event and one agent-SQL `sqlx::query` INFO event.
    fn emitted(rust_log: Option<&str>) -> String {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(env_filter(rust_log).expect("filter"))
            .with_target(true)
            .with_ansi(false)
            .with_writer(move || BufSink(sink.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "audit_stream", "audit-row");
            tracing::info!("operational-line");
            tracing::info!(target: "sqlx::query", "select agent_sql");
        });
        let bytes = buf.lock().expect("buffer").clone();
        String::from_utf8(bytes).expect("utf8")
    }

    struct BufSink(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buffer").extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn unset_or_empty_rust_log_logs_info_but_not_agent_sql() {
        for unset in [None, Some(""), Some("  ")] {
            let out = emitted(unset);
            assert!(out.contains("operational-line"), "{unset:?}: {out}");
            assert!(out.contains("audit-row"), "{unset:?}: {out}");
            assert!(!out.contains("agent_sql"), "{unset:?}: {out}");
        }
    }

    #[test]
    fn audit_stream_stays_at_info_under_a_quiet_rust_log() {
        let out = emitted(Some("warn"));
        assert!(out.contains("audit-row"), "{out}");
        assert!(!out.contains("operational-line"), "{out}");
    }
}
