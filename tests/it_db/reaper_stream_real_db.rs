//! An `abandoned` row the reaper writes reaches the stream sinks like any
//! other audit row (plan 101 U2): a TCP syslog receiver on loopback gets the
//! reaped row, with the id and fields of the durable `audit_calls` row.

use std::time::Duration;

use crate::common::audit::calls_for_request;
use crate::common::cleanup::delete_audit_calls;
use crate::common::env::state_pool;
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::audit::reaper::{self, ReapCursor};
use db_mcp_gateway::audit::stream::{StreamSinks, SyslogTransport};
use db_mcp_gateway::audit::{self, CallIntent};
use db_mcp_gateway::exec::Access;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Read RFC 5425 frames until one carries `request_id`; its JSON body.
async fn body_for(reader: &mut BufReader<tokio::net::TcpStream>, request_id: &str) -> Value {
    loop {
        let mut len = Vec::new();
        reader
            .read_until(b' ', &mut len)
            .await
            .expect("frame length");
        let len: usize = std::str::from_utf8(&len[..len.len() - 1])
            .unwrap()
            .parse()
            .expect("numeric frame length");
        let mut message = vec![0; len];
        reader.read_exact(&mut message).await.expect("frame body");
        let message = String::from_utf8(message).unwrap();
        let body: Value = serde_json::from_str(&message[message.find('{').unwrap()..]).unwrap();
        if body["request_id"] == request_id {
            return body;
        }
    }
}

#[tokio::test]
#[serial_test::serial(world)]
async fn reaped_row_reaches_the_stream_sink() {
    let p = state_pool().await;
    let user = format!("reaper-stream-{}", Uuid::new_v4().simple());
    let orphan = Uuid::new_v4();
    audit::intent::record(
        &p,
        &CallIntent {
            request_id: orphan,
            user_sub: &user,
            user_email: "reaper-stream@example.com",
            tool: "run_query",
            server: "prod",
            database: "app",
            db_type: Some("postgres"),
            access: Access::ReadWrite,
            sql: Some("UPDATE t SET x = 1"),
            reason: Some("backfill"),
            upstream_actor: Some("alice@example.com"),
            upstream_run_id: Some("run-9"),
        },
    )
    .await
    .expect("intent written");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let sinks = StreamSinks::syslog("127.0.0.1".into(), port, SyslogTransport::Tcp);
    let tasks = DetachedTasks::new();

    let reaped = reaper::sweep(
        &p,
        Duration::ZERO,
        &mut ReapCursor::default(),
        &sinks,
        &tasks,
    )
    .await
    .expect("sweep runs");
    assert!(reaped.is_some_and(|n| n >= 1), "{reaped:?}");

    let (socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("sink connected")
        .unwrap();
    let mut reader = BufReader::new(socket);
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        body_for(&mut reader, &orphan.to_string()),
    )
    .await
    .expect("reaped row streamed");

    let durable = calls_for_request(&p, &orphan.to_string()).await;
    assert_eq!(durable.len(), 1, "{durable:?}");
    assert_eq!(body["outcome"], "abandoned");
    assert_eq!(body["user_sub"], user.as_str());
    assert_eq!(body["sql"], "UPDATE t SET x = 1");
    assert_eq!(body["reason"], "backfill");
    assert_eq!(body["upstream_actor"], "alice@example.com");
    assert_eq!(body["upstream_run_id"], "run-9");
    assert_eq!(
        body["error_message"].as_str(),
        durable[0].1.as_deref(),
        "streamed row is the durable row"
    );
    let durable_id: Uuid = sqlx::query_scalar("SELECT id FROM audit_calls WHERE request_id = $1")
        .bind(orphan.to_string())
        .fetch_one(&p)
        .await
        .unwrap();
    assert_eq!(body["id"], durable_id.to_string());

    delete_audit_calls(&p, &user).await;
}
