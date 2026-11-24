//! A pooled Redis connection the server closed while it sat idle (a server
//! `timeout`, a proxy, a NAT) is replaced on its next use: the read runs
//! again on a fresh connection instead of failing `unavailable`. Runs
//! against Redis and Dragonfly.
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use std::collections::BTreeSet;

use redis::aio::MultiplexedConnection;
use serde_json::json;

use crate::common::redis_target::{
    Flavor, READ_USER, adapter, admin, admin_cmd, delete_keys, ok, unique_key,
};
use db_mcp_gateway::exec::PoolSizing;

/// The ids of the clients the server lists, minus `side`'s own, that are
/// not known to be another ACL user. Redis prints `user=`; Dragonfly does
/// not, so there the id set alone tells connections apart.
async fn gateway_client_ids(side: &mut MultiplexedConnection) -> BTreeSet<String> {
    let own = match admin_cmd(side, &["CLIENT", "ID"]).await {
        redis::Value::Int(id) => id.to_string(),
        other => panic!("CLIENT ID: {other:?}"),
    };
    let list = match admin_cmd(side, &["CLIENT", "LIST"]).await {
        redis::Value::BulkString(bytes) => String::from_utf8(bytes).expect("UTF-8 CLIENT LIST"),
        redis::Value::VerbatimString { text, .. } => text,
        other => panic!("CLIENT LIST: {other:?}"),
    };
    list.lines()
        .filter(|line| {
            line.split(' ')
                .find_map(|field| field.strip_prefix("user="))
                .is_none_or(|user| user == READ_USER)
        })
        .filter_map(|line| line.split(' ').find_map(|field| field.strip_prefix("id=")))
        .filter(|id| *id != own)
        .map(str::to_string)
        .collect()
}

/// Close only the connections that appeared since `before`: the adapter's.
/// Every other client of the shared server keeps its connection.
async fn kill_new_clients(side: &mut MultiplexedConnection, before: &BTreeSet<String>) -> usize {
    let new: Vec<String> = gateway_client_ids(side)
        .await
        .difference(before)
        .cloned()
        .collect();
    for id in &new {
        admin_cmd(side, &["CLIENT", "KILL", "ID", id]).await;
    }
    new.len()
}

#[tokio::test]
// Serial: telling the adapter's connection apart by "appeared since
// `before`" needs no other test opening connections meanwhile (Dragonfly
// lists no ACL user to filter on).
#[serial_test::serial(world)]
async fn a_read_on_a_connection_closed_while_idle_reconnects_once() {
    for flavor in Flavor::ALL {
        let sizing = PoolSizing {
            max_connections: 1,
            ..PoolSizing::default()
        };
        let mut side = admin(flavor).await;
        let before = gateway_client_ids(&mut side).await;
        let a = adapter(flavor, sizing).await;
        let key = unique_key("idle");
        admin_cmd(&mut side, &["SET", &key, "still here"]).await;
        let get = format!(r#"["GET","{key}"]"#);

        // Opens the pool's one connection and leaves it idle.
        ok(&a, flavor, &get, 10).await;
        let killed = kill_new_clients(&mut side, &before).await;
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
