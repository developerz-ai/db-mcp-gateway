use std::io::Write;
use std::sync::{Arc, Mutex};

use super::*;

const APP: Origin<'static> = Origin {
    server: "prod",
    database: "app",
    role: "app_ro",
    request_id: None,
};

#[test]
fn pool_and_io_errors_are_unavailable() {
    assert!(matches!(
        classify(sqlx::Error::PoolTimedOut, &APP, ""),
        ExecError::Unavailable
    ));
    assert!(matches!(
        classify(io_reset(), &APP, ""),
        ExecError::Unavailable
    ));
}

#[test]
fn opaque_errors_stay_opaque() {
    assert!(matches!(
        classify(sqlx::Error::RowNotFound, &APP, ""),
        ExecError::Sql
    ));
    assert_eq!(
        AcquireFailure::of(&sqlx::Error::PoolTimedOut, &APP),
        AcquireFailure::Other
    );
}

fn io_reset() -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
}

#[test]
fn lost_connection_at_write_commit_is_indeterminate() {
    assert!(matches!(
        classify_commit(io_reset(), Access::ReadWrite, &APP, ""),
        ExecError::CommitIndeterminate
    ));
    assert!(matches!(
        classify_commit(
            sqlx::Error::Protocol("eof".into()),
            Access::ReadWrite,
            &APP,
            ""
        ),
        ExecError::CommitIndeterminate
    ));
}

#[test]
fn lost_connection_at_read_commit_stays_unavailable() {
    assert!(matches!(
        classify_commit(io_reset(), Access::ReadOnly, &APP, ""),
        ExecError::Unavailable
    ));
}

#[test]
fn only_sqlstate_0a000_is_feature_not_supported() {
    assert!(sqlstate_is_feature_not_supported(Some("0A000")));
    assert!(!sqlstate_is_feature_not_supported(Some("42501")));
    assert!(!sqlstate_is_feature_not_supported(None));
    assert!(!is_feature_not_supported(&sqlx::Error::PoolTimedOut));
}

#[test]
fn only_the_targets_own_rollbacks_are_retryable() {
    for code in ["40001", "40P01", "25P03", "25P04"] {
        assert!(rolled_back_by_the_target(code), "{code}");
    }
    // 40002 is a constraint violation, 25006 a write in a read-only
    // transaction: both are about the statement.
    for code in ["40002", "40000", "25006", "25P02", "42601"] {
        assert!(!rolled_back_by_the_target(code), "{code}");
    }
}

/// Collects what the JSON subscriber would print.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The log line names the request and the database as event fields: the
/// production subscriber prints no span (`startup::logging`), so a field
/// that lived only on the tool-dispatch span would not be on the line.
#[test]
fn a_target_error_log_line_names_its_request_and_database() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_writer(move || writer.clone())
        .finish();
    let request_id = Uuid::new_v4();
    let origin = Origin {
        request_id: Some(request_id),
        ..APP
    };
    tracing::subscriber::with_default(subscriber, || {
        let _ = classify(io_reset(), &origin, "SELECT 1");
        log_discarded(&io_reset(), None, "connection reset failed; discarding");
    });

    let logged = String::from_utf8(captured.0.lock().expect("log buffer").clone()).expect("UTF-8");
    let lines: Vec<serde_json::Value> = logged
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
        .collect();
    assert_eq!(lines.len(), 2, "{logged}");
    assert_eq!(lines[0]["request_id"], request_id.to_string());
    assert_eq!(lines[0]["server"], "prod");
    assert_eq!(lines[0]["db"], "app");
    assert_eq!(lines[0]["error_kind"], "io");
    assert!(
        !logged.contains("app_ro"),
        "the role is never logged: {logged}"
    );
    // Work no request asked for carries no request id — and no empty one.
    assert!(lines[1].get("request_id").is_none(), "{logged}");
}
