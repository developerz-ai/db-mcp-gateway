//! Real-server tests for `RedisAdapter::execute`, run against Redis AND
//! Dragonfly (`target-redis` :6380, `target-dragonfly` :6381). Covers the
//! result shapes as shipped, the row cap, the rejector (before any network
//! call), ACL refusals and credentials. The timeout path lives in
//! `redis_timeout_real_db.rs`.

use crate::common::redis_target::{
    DB_INDEX, Flavor, KEY_PREFIX, READ_USER, adapter, admin, admin_cmd, database, delete_keys,
    server, unique_key,
};
use db_mcp_gateway::config::Password;
use db_mcp_gateway::exec::{
    Access, DbAdapter, ExecError, ExecQuery, ExecResult, PoolSizing, RedisAdapter, RejectionKind,
};
use serde_json::{Value, json};

async fn run(a: &RedisAdapter, argv: &str, row_limit: u32) -> Result<ExecResult, ExecError> {
    a.execute(ExecQuery {
        sql: argv,
        binds: &[],
        statement_timeout_ms: None,
        row_limit,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: uuid::Uuid::new_v4(),
    })
    .await
}

async fn ok(a: &RedisAdapter, flavor: Flavor, argv: &str, row_limit: u32) -> ExecResult {
    run(a, argv, row_limit)
        .await
        .unwrap_or_else(|err| panic!("{}: {argv} failed: {err:?}", flavor.name()))
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn get_and_hgetall_answer_in_their_documented_shapes() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (s, h) = (unique_key("str"), unique_key("hash"));
        admin_cmd(&mut side, &["SET", &s, "hello"]).await;
        admin_cmd(&mut side, &["HSET", &h, "name", "ada", "age", "36"]).await;

        let get = ok(&a, flavor, &format!(r#"["get","{s}"]"#), 100).await;
        let missing = ok(&a, flavor, &format!(r#"["GET","{s}:nope"]"#), 100).await;
        let hash = ok(&a, flavor, &format!(r#"["HGETALL","{h}"]"#), 100).await;
        delete_keys(&mut side, &[&s, &h]).await;

        assert_eq!(get.columns, ["value"], "{}", flavor.name());
        assert_eq!(get.rows, vec![vec![json!("hello")]], "{}", flavor.name());
        assert!(!get.truncated);
        assert_eq!(get.rows_affected, None);
        assert_eq!(missing.rows, vec![vec![Value::Null]], "{}", flavor.name());
        assert_eq!(hash.columns, ["field", "value"], "{}", flavor.name());
        let mut pairs = hash.rows.clone();
        pairs.sort_by_key(|row| row[0].to_string());
        assert_eq!(
            pairs,
            vec![
                vec![json!("age"), json!("36")],
                vec![json!("name"), json!("ada")]
            ],
            "{}",
            flavor.name()
        );
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn zrange_withscores_pairs_members_with_scores() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let z = unique_key("zset");
        admin_cmd(&mut side, &["ZADD", &z, "1", "a", "2.5", "b"]).await;
        let out = ok(
            &a,
            flavor,
            &format!(r#"["ZRANGE","{z}",0,-1,"WITHSCORES"]"#),
            100,
        )
        .await;
        let plain = ok(&a, flavor, &format!(r#"["zrange","{z}","0","-1"]"#), 100).await;
        delete_keys(&mut side, &[&z]).await;

        assert_eq!(out.columns, ["member", "score"], "{}", flavor.name());
        assert_eq!(out.rows.len(), 2, "{}", flavor.name());
        assert_eq!(out.rows[0][0], json!("a"));
        assert_eq!(out.rows[1][0], json!("b"));
        // RESP2 scores are the server's own decimal text.
        let score: f64 = out.rows[1][1]
            .as_str()
            .expect("score text")
            .parse()
            .unwrap();
        assert!((score - 2.5).abs() < f64::EPSILON, "{}", flavor.name());
        assert_eq!(plain.columns, ["value"]);
        assert_eq!(plain.rows, vec![vec![json!("a")], vec![json!("b")]]);
    }
}

/// `SCAN` rows lead with the next cursor; following it to `0` finds every
/// seeded key, through the clamped `COUNT`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn scan_rows_carry_the_cursor_and_find_every_key() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let tag = unique_key("scan");
        let keys: Vec<String> = (0..5).map(|i| format!("{tag}:{i}")).collect();
        for key in &keys {
            admin_cmd(&mut side, &["SET", key, "v"]).await;
        }
        let mut found = Vec::new();
        let mut cursor = "0".to_string();
        for _ in 0..1000 {
            let argv = format!(r#"["SCAN","{cursor}","MATCH","{tag}:*"]"#);
            let page = ok(&a, flavor, &argv, 10_000).await;
            assert_eq!(page.columns, ["next_cursor", "key"], "{}", flavor.name());
            assert!(!page.rows.is_empty(), "a page always carries its cursor");
            cursor = page.rows[0][0].as_str().expect("cursor").to_string();
            found.extend(
                page.rows
                    .iter()
                    .filter_map(|r| r[1].as_str().map(str::to_string)),
            );
            if cursor == "0" {
                break;
            }
        }
        let key_refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        delete_keys(&mut side, &key_refs).await;
        found.sort();
        assert_eq!(found, keys, "{}", flavor.name());
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn row_limit_truncates_and_flags_it() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let l = unique_key("list");
        let mut argv = vec!["RPUSH", l.as_str()];
        let items: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        argv.extend(items.iter().map(String::as_str));
        admin_cmd(&mut side, &argv).await;
        let capped = ok(&a, flavor, &format!(r#"["LRANGE","{l}",0,-1]"#), 4).await;
        let exact = ok(&a, flavor, &format!(r#"["LRANGE","{l}",0,-1]"#), 10).await;
        delete_keys(&mut side, &[&l]).await;

        assert_eq!(capped.rows.len(), 4, "{}", flavor.name());
        assert!(capped.truncated, "{}", flavor.name());
        assert_eq!(capped.rows[3], vec![json!("3")]);
        assert_eq!(exact.rows.len(), 10);
        assert!(!exact.truncated);
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn xrange_entries_carry_fields_as_an_object() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let s = unique_key("stream");
        admin_cmd(
            &mut side,
            &["XADD", &s, "1-1", "event", "login", "user", "ada"],
        )
        .await;
        let out = ok(&a, flavor, &format!(r#"["XRANGE","{s}","-","+"]"#), 100).await;
        delete_keys(&mut side, &[&s]).await;

        assert_eq!(out.columns, ["id", "fields"], "{}", flavor.name());
        assert_eq!(
            out.rows,
            vec![vec![json!("1-1"), json!({"event": "login", "user": "ada"})]],
            "{}",
            flavor.name()
        );
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_binary_value_comes_back_as_base64() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let b = unique_key("bin");
        redis::cmd("SET")
            .arg(&b)
            .arg(&[0xff_u8, 0x00, 0xfe][..])
            .exec_async(&mut side)
            .await
            .expect("seed binary");
        let out = ok(&a, flavor, &format!(r#"["GET","{b}"]"#), 10).await;
        delete_keys(&mut side, &[&b]).await;
        assert_eq!(
            out.rows,
            vec![vec![json!({"base64": "/wD+"})]],
            "{}",
            flavor.name()
        );
    }
}

/// The rejector runs before any network call: the adapter points at a port
/// nothing listens on, yet the answer is `Forbidden`, not `Unavailable`. On
/// the real servers the key is still absent afterwards.
#[tokio::test]
#[serial_test::parallel(world)]
async fn set_is_refused_before_any_network_call() {
    let mut nowhere = server(Flavor::Redis);
    nowhere.port = 1;
    let dead = RedisAdapter::open(&nowhere, &database(), PoolSizing::default())
        .await
        .expect("open is lazy");
    let refused = run(&dead, r#"["SET","gw:x","v"]"#, 10).await;
    assert!(
        matches!(&refused, Err(ExecError::Forbidden(reason)) if reason.contains("`SET`")),
        "{refused:?}"
    );

    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let k = unique_key("never");
        for argv in [
            format!(r#"["SET","{k}","v"]"#),
            format!(r#"["eval","redis.call('set','{k}','v')","0"]"#),
            r#"["FLUSHDB"]"#.to_string(),
            r#"["KEYS","*"]"#.to_string(),
        ] {
            let err = run(&a, &argv, 10).await.expect_err(&argv);
            assert!(matches!(err, ExecError::Forbidden(_)), "{argv}: {err:?}");
        }
        let mut side = admin(flavor).await;
        let exists = admin_cmd(&mut side, &["EXISTS", &k]).await;
        assert_eq!(exists, redis::Value::Int(0), "{}", flavor.name());
    }
}

/// A key outside the ACL user's pattern is the server's `NOPERM`, surfaced
/// as `permission_denied` with the ACL username redacted.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_key_outside_the_acl_pattern_is_permission_denied() {
    assert!(!"other:x".starts_with(KEY_PREFIX));
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let err = run(&a, r#"["GET","other:x"]"#, 10)
            .await
            .expect_err("NOPERM");
        let ExecError::Rejected(rejection) = err else {
            panic!("{}: expected Rejected, got {err:?}", flavor.name());
        };
        assert_eq!(
            rejection.kind(),
            RejectionKind::PermissionDenied,
            "{rejection}"
        );
        assert_eq!(rejection.sqlstate(), "NOPERM");
        assert!(!rejection.message().contains(READ_USER), "{rejection}");
        // The connection survived the server error: the next read works.
        let k = unique_key("after");
        let next = run(&a, &format!(r#"["EXISTS","{k}"]"#), 10).await;
        assert_eq!(next.expect("next read").rows, vec![vec![json!(0)]]);
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn a_wrong_password_is_a_connection_error_and_marks_the_adapter_stale() {
    for flavor in Flavor::ALL {
        let _ = adapter(flavor, PoolSizing::default()).await;
        let mut db = database();
        db.password = Password::Literal("wrong-password".into());
        let a = RedisAdapter::open(&server(flavor), &db, PoolSizing::default())
            .await
            .expect("open is lazy");
        let err = run(&a, r#"["DBSIZE"]"#, 10)
            .await
            .expect_err("bad password");
        assert!(
            matches!(err, ExecError::Connection),
            "{}: {err:?}",
            flavor.name()
        );
        assert!(a.is_stale(), "{}", flavor.name());
        assert_eq!(DB_INDEX, db.name);
    }
}
