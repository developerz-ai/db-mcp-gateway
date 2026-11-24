//! A pooled Redis connection the server closed while it sat idle (a server
//! `timeout`, a proxy, a NAT) is replaced on its next use: the read runs
//! again on a fresh connection instead of failing `unavailable`. Runs
//! against Redis and Dragonfly.
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use redis::aio::MultiplexedConnection;
use serde_json::json;

use crate::common::redis_target::{Flavor, adapter, admin, admin_cmd, delete_keys, ok, unique_key};
use db_mcp_gateway::exec::PoolSizing;

/// Close every client connection but `side`'s own. `CLIENT KILL USER` would
/// be narrower, but Dragonfly has no `USER` filter, hence the serial test.
async fn kill_other_clients(side: &mut MultiplexedConnection) -> usize {
    let own = match admin_cmd(side, &["CLIENT", "ID"]).await {
        redis::Value::Int(id) => id.to_string(),
        other => panic!("CLIENT ID: {other:?}"),
    };
    let list = match admin_cmd(side, &["CLIENT", "LIST"]).await {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes).expect("UTF-8 CLIENT LIST"),
        redis::Value::VerbatimString { text, .. } => text,
        other => panic!("CLIENT LIST: {other:?}"),
    };
    let ids: Vec<String> = list
        .lines()
        .filter_map(|line| line.split(' ').find_map(|field| field.strip_prefix("id=")))
        .filter(|id| *id != own)
        .map(str::to_string)
        .collect();
    for id in &ids {
        admin_cmd(side, &["CLIENT", "KILL", "ID", id]).await;
    }
    ids.len()
}

#[tokio::test]
#[serial_test::serial(world)]
async fn a_read_on_a_connection_closed_while_idle_reconnects_once() {
    for flavor in Flavor::ALL {
        let sizing = PoolSizing {
            max_connections: 1,
            ..PoolSizing::default()
        };
        let a = adapter(flavor, sizing).await;
        let mut side = admin(flavor).await;
        let key = unique_key("idle");
        admin_cmd(&mut side, &["SET", &key, "still here"]).await;
        let get = format!(r#"["GET","{key}"]"#);

        // Opens the pool's one connection and leaves it idle.
        ok(&a, flavor, &get, 10).await;
        let killed = kill_other_clients(&mut side).await;
        let after = ok(&a, flavor, &get, 10).await;
        // The replacement went back to the pool and keeps serving.
        let again = ok(&a, flavor, &get, 10).await;
        delete_keys(&mut side, &[&key]).await;

        assert!(
            killed >= 1,
            "{}: no gateway connection to kill",
            flavor.name()
        );
        assert_eq!(
            after.rows,
            vec![vec![json!("still here")]],
            "{}",
            flavor.name()
        );
        assert_eq!(again.rows, after.rows, "{}", flavor.name());
    }
}
