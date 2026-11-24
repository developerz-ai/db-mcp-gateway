//! A7: `/readyz` against a state DB that rejects the password logs the
//! failure's class, never the `sqlx::Error` text or the DSN (MUST #1).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use db_mcp_gateway::config::Config;
use db_mcp_gateway::transport;

use crate::common::env::state_db_url;
use crate::common::offline::authless_state;

const SECRET: &str = "hunter2-probe-secret";

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer").extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn readyz_logs_the_error_class_not_the_password() {
    let mut url = url::Url::parse(&state_db_url()).expect("state DB url");
    url.set_password(Some(SECRET)).expect("password");
    let mut state = authless_state();
    state.mcp.state_db = PgPoolOptions::new()
        .connect_lazy(url.as_str())
        .expect("lazy pool");
    let app = transport::router(&Config::default(), state).expect("router");

    let captured = Captured::default();
    let sink = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let response = app
        .oneshot(
            Request::get("/readyz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("readyz answers");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let logs = String::from_utf8(captured.0.lock().expect("buffer").clone()).expect("utf8");
    assert!(
        logs.contains("readyz: state db query failed"),
        "no probe line: {logs}"
    );
    assert!(logs.contains("database/28P01"), "no error class: {logs}");
    assert!(!logs.contains(SECRET), "password leaked: {logs}");
    assert!(!logs.contains("postgres://"), "DSN leaked: {logs}");
}
