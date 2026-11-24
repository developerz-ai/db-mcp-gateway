//! A pooled Redis connection the server closed while it sat idle (a server
//! `timeout`, a proxy, a NAT) is replaced on its next use: the read runs
//! again on a fresh connection instead of failing `unavailable`. Runs
//! against Redis and Dragonfly.
//!
//! Audit assertion intentionally skipped: these drive the adapter directly,
//! never the tool-dispatch path that writes audit rows.

use std::collections::BTreeMap;

use redis::aio::MultiplexedConnection;
use serde_json::json;

use crate::common::redis_target::{
    Flavor, READ_USER, adapter, admin, admin_cmd, delete_keys, ok, unique_key,
};
use db_mcp_gateway::exec::PoolSizing;

/// The clients the server lists, minus `side`'s own, that are not known to
/// be another ACL user, as `id → CLIENT LIST line`. Redis prints `user=`;
/// Dragonfly does not, so there the id set alone tells connections apart.
async fn gateway_clients(side: &mut MultiplexedConnection) -> BTreeMap<String, String> {
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
        .filter(|line| field(line, "user=").is_none_or(|user| user == READ_USER))
        .filter_map(|line| Some((field(line, "id=")?.to_string(), line.to_string())))
        .filter(|(id, _)| *id != own)
        .collect()
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split(' ').find_map(|field| field.strip_prefix(key))
}

/// Close the one connection that appeared since `before` and last ran a
/// `GET` (where the server reports the last command): the adapter's. Every
/// other client of the shared server keeps its connection.
async fn kill_new_client(side: &mut MultiplexedConnection, before: &BTreeMap<String, String>) {
    let candidates: Vec<String> = gateway_clients(side)
        .await
        .into_iter()
        .filter(|(id, line)| {
            !before.contains_key(id)
                && field(line, "cmd=").is_none_or(|cmd| cmd.eq_ignore_ascii_case("get"))
        })
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "exactly the adapter's connection is new: {candidates:?}"
    );
    admin_cmd(side, &["CLIENT", "KILL", "ID", &candidates[0]]).await;
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
        let before = gateway_clients(&mut side).await;
        let a = adapter(flavor, sizing).await;
        let key = unique_key("idle");
        admin_cmd(&mut side, &["SET", &key, "still here"]).await;
        let get = format!(r#"["GET","{key}"]"#);

        // Opens the pool's one connection and leaves it idle.
        ok(&a, flavor, &get, 10).await;
        kill_new_client(&mut side, &before).await;
        let after = ok(&a, flavor, &get, 10).await;
        // The replacement went back to the pool and keeps serving.
        let again = ok(&a, flavor, &get, 10).await;
        delete_keys(&mut side, &[&key]).await;

        assert_eq!(
            after.rows,
            vec![vec![json!("still here")]],
            "{}",
            flavor.name()
        );
        assert_eq!(again.rows, after.rows, "{}", flavor.name());
    }
}
