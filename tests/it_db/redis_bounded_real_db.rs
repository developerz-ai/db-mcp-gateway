//! Every allowlisted range and count is bounded at the source, against
//! Redis AND Dragonfly: ranges and counts are cut to `row_limit + 1`
//! server-side and whole-collection reads are cursor loops. Set algebra and
//! value sizes: `redis_bounded_values_real_db.rs`.

use std::time::{Duration, Instant};

use crate::common::redis_target::{
    Flavor, adapter, admin, admin_cmd, delete_keys, ok, seed, texts, unique_key,
};
use db_mcp_gateway::exec::PoolSizing;
use serde_json::json;

/// `SRANDMEMBER k -2000000000` on a one-member set would make the server
/// build a two-billion-element reply; clamped, it is `cap` repeats, at once.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_huge_random_count_is_clamped_keeping_its_sign() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let s = unique_key("rand");
        admin_cmd(&mut side, &["SADD", &s, "only"]).await;
        let started = Instant::now();
        let repeats = ok(
            &a,
            flavor,
            &format!(r#"["SRANDMEMBER","{s}","-2000000000"]"#),
            5,
        )
        .await;
        let distinct = ok(
            &a,
            flavor,
            &format!(r#"["SRANDMEMBER","{s}","2000000000"]"#),
            5,
        )
        .await;
        delete_keys(&mut side, &[&s]).await;

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{}",
            flavor.name()
        );
        assert_eq!(repeats.rows.len(), 5, "{}", flavor.name());
        assert!(repeats.truncated, "negative count: repeats past the cap");
        assert!(repeats.rows.iter().all(|r| r[0] == json!("only")));
        assert_eq!(
            distinct.rows,
            vec![vec![json!("only")]],
            "{}",
            flavor.name()
        );
        assert!(!distinct.truncated);
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn list_and_index_ranges_are_cut_at_the_source() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (l, z) = (unique_key("long"), unique_key("zlong"));
        let items: Vec<String> = (0..2_000).map(|i| i.to_string()).collect();
        seed(&mut side, &["RPUSH", &l], &items).await;
        let scored: Vec<String> = (0..2_000)
            .flat_map(|i| [i.to_string(), format!("m{i}")])
            .collect();
        seed(&mut side, &["ZADD", &z], &scored).await;

        let all = ok(&a, flavor, &format!(r#"["LRANGE","{l}",0,-1]"#), 10).await;
        let tail = ok(&a, flavor, &format!(r#"["LRANGE","{l}",-3,-1]"#), 10).await;
        let top = ok(
            &a,
            flavor,
            &format!(r#"["ZREVRANGE","{z}",0,-1,"WITHSCORES"]"#),
            3,
        )
        .await;
        let rev = ok(&a, flavor, &format!(r#"["ZRANGE","{z}",0,-1,"REV"]"#), 2).await;
        delete_keys(&mut side, &[&l, &z]).await;

        let first_ten: Vec<String> = (0..10).map(|i| i.to_string()).collect();
        assert_eq!(texts(&all, 0), first_ten, "{}", flavor.name());
        assert!(all.truncated);
        assert_eq!(
            texts(&tail, 0),
            ["1997", "1998", "1999"],
            "{}",
            flavor.name()
        );
        assert!(!tail.truncated);
        assert_eq!(top.columns, ["member", "score"]);
        assert_eq!(
            texts(&top, 0),
            ["m1999", "m1998", "m1997"],
            "{}",
            flavor.name()
        );
        assert!(top.truncated);
        assert_eq!(texts(&rev, 0), ["m1999", "m1998"], "{}", flavor.name());
    }
}

#[tokio::test]
#[serial_test::parallel(world)]
async fn score_lex_and_stream_ranges_get_a_limit() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (z, s) = (unique_key("zscore"), unique_key("stream"));
        let scored: Vec<String> = (0..50)
            .flat_map(|i| [i.to_string(), format!("m{i:02}")])
            .collect();
        seed(&mut side, &["ZADD", &z], &scored).await;
        for i in 1..=30 {
            admin_cmd(
                &mut side,
                &["XADD", &s, &format!("{i}-0"), "n", &i.to_string()],
            )
            .await;
        }
        let by_score = format!(r#"["ZRANGE","{z}","-inf","+inf","BYSCORE","WITHSCORES"]"#);
        let by_score = ok(&a, flavor, &by_score, 5).await;
        let all_limit = format!(r#"["ZRANGEBYSCORE","{z}","-inf","+inf","LIMIT",0,-1]"#);
        let all_limit = ok(&a, flavor, &all_limit, 5).await;
        let small_limit = format!(r#"["ZRANGEBYSCORE","{z}","-inf","+inf","LIMIT",10,2]"#);
        let small_limit = ok(&a, flavor, &small_limit, 5).await;
        let stream = ok(&a, flavor, &format!(r#"["XRANGE","{s}","-","+"]"#), 5).await;
        delete_keys(&mut side, &[&z, &s]).await;

        assert_eq!(
            texts(&by_score, 0),
            ["m00", "m01", "m02", "m03", "m04"],
            "{}",
            flavor.name()
        );
        assert!(by_score.truncated);
        assert_eq!(all_limit.rows.len(), 5);
        assert!(all_limit.truncated, "LIMIT 0 -1 (all) is clamped");
        assert_eq!(
            texts(&small_limit, 0),
            ["m10", "m11"],
            "a smaller LIMIT is kept"
        );
        assert!(!small_limit.truncated);
        assert_eq!(stream.rows.len(), 5, "{}", flavor.name());
        assert!(stream.truncated);
        assert_eq!(stream.rows[0][0], json!("1-0"));
    }
}

/// Past the listpack threshold `HSCAN`/`SSCAN` page; the loop stops at the
/// cap with distinct items, and a small collection still comes back whole.
#[tokio::test]
#[serial_test::parallel(world)]
async fn whole_collection_reads_stop_at_the_row_limit() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (h, set, small) = (
            unique_key("bighash"),
            unique_key("bigset"),
            unique_key("small"),
        );
        let fields: Vec<String> = (0..1_500)
            .flat_map(|i| [format!("f{i}"), format!("v{i}")])
            .collect();
        seed(&mut side, &["HSET", &h], &fields).await;
        let members: Vec<String> = (0..1_500).map(|i| format!("m{i}")).collect();
        seed(&mut side, &["SADD", &set], &members).await;
        admin_cmd(&mut side, &["HSET", &small, "a", "1", "b", "2"]).await;

        let hgetall = ok(&a, flavor, &format!(r#"["HGETALL","{h}"]"#), 100).await;
        let hkeys = ok(&a, flavor, &format!(r#"["HKEYS","{h}"]"#), 7).await;
        let hvals = ok(&a, flavor, &format!(r#"["HVALS","{h}"]"#), 7).await;
        let smembers = ok(&a, flavor, &format!(r#"["SMEMBERS","{set}"]"#), 50).await;
        let whole = ok(&a, flavor, &format!(r#"["HGETALL","{small}"]"#), 100).await;
        let missing = ok(&a, flavor, &format!(r#"["SMEMBERS","{small}:none"]"#), 100).await;
        delete_keys(&mut side, &[&h, &set, &small]).await;

        assert_eq!(hgetall.columns, ["field", "value"], "{}", flavor.name());
        assert_eq!(hgetall.rows.len(), 100);
        assert!(hgetall.truncated);
        for row in &hgetall.rows {
            let field = row[0].as_str().expect("field");
            assert_eq!(
                row[1],
                json!(format!("v{}", &field[1..])),
                "pairs stay paired"
            );
        }
        let mut distinct = texts(&hgetall, 0);
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 100, "no repeats");
        assert_eq!(
            (hkeys.columns.clone(), hkeys.rows.len(), hkeys.truncated),
            (vec!["value".to_string()], 7, true)
        );
        assert!(texts(&hkeys, 0).iter().all(|f| f.starts_with('f')));
        assert!(texts(&hvals, 0).iter().all(|v| v.starts_with('v')));
        assert_eq!(smembers.rows.len(), 50);
        assert!(smembers.truncated);
        let mut pairs = whole.rows.clone();
        pairs.sort_by_key(|r| r[0].to_string());
        assert_eq!(
            pairs,
            vec![vec![json!("a"), json!("1")], vec![json!("b"), json!("2")]]
        );
        assert!(!whole.truncated);
        assert!(missing.rows.is_empty() && !missing.truncated);
    }
}
