//! Bounds that cannot be a rewrite, against Redis AND Dragonfly: set
//! algebra past the row limit is refused, and a value past the byte budget
//! is never fetched — with server-side evidence from `INFO commandstats`.

use crate::common::redis_target::{
    Flavor, adapter, admin, admin_cmd, calls, delete_keys, ok, run, seed, texts, unique_key,
};
use db_mcp_gateway::exec::{ExecError, MAX_RESULT_BYTES, PoolSizing};
use serde_json::{Value, json};

#[tokio::test]
#[serial_test::parallel(world)]
async fn set_algebra_past_the_row_limit_is_refused() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (x, y) = (unique_key("sx"), unique_key("sy"));
        let members: Vec<String> = (0..30).map(|i| format!("m{i}")).collect();
        seed(&mut side, &["SADD", &x], &members).await;
        admin_cmd(&mut side, &["SADD", &y, "m1", "m2", "other"]).await;

        let union = run(&a, &format!(r#"["SUNION","{x}","{y}"]"#), 10).await;
        let inter = ok(&a, flavor, &format!(r#"["SINTER","{x}","{y}"]"#), 10).await;
        let diff = ok(&a, flavor, &format!(r#"["SDIFF","{y}","{x}"]"#), 10).await;
        let big_diff = run(&a, &format!(r#"["SDIFF","{x}","{y}"]"#), 10).await;
        delete_keys(&mut side, &[&x, &y]).await;

        match union {
            Err(ExecError::Forbidden(reason)) => {
                assert!(
                    reason.contains("`SUNION`") && reason.contains("33"),
                    "{reason}"
                );
            }
            other => panic!("{}: SUNION past the limit: {other:?}", flavor.name()),
        }
        assert!(
            matches!(big_diff, Err(ExecError::Forbidden(_))),
            "{big_diff:?}"
        );
        let mut inter = texts(&inter, 0);
        inter.sort();
        assert_eq!(
            inter,
            ["m1", "m2"],
            "min(SCARD) = 3 fits: {}",
            flavor.name()
        );
        assert_eq!(texts(&diff, 0), ["other"]);
    }
}

/// A value past the byte budget is never fetched: zero rows, `truncated`.
/// `SETRANGE` builds the 32 MiB + 1 string server-side in one command.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_value_past_the_byte_budget_is_not_fetched() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (big, small, h) = (unique_key("big"), unique_key("small"), unique_key("bigh"));
        admin_cmd(
            &mut side,
            &["SETRANGE", &big, &MAX_RESULT_BYTES.to_string(), "x"],
        )
        .await;
        admin_cmd(&mut side, &["SET", &small, "tiny"]).await;

        let get = ok(&a, flavor, &format!(r#"["GET","{big}"]"#), 10).await;
        let whole_range = ok(&a, flavor, &format!(r#"["GETRANGE","{big}",0,-1]"#), 10).await;
        let slice = ok(&a, flavor, &format!(r#"["GETRANGE","{big}",-1,-1]"#), 10).await;
        let mget = ok(
            &a,
            flavor,
            &format!(r#"["MGET","{small}","{big}","{small}"]"#),
            10,
        )
        .await;
        let strlen = ok(&a, flavor, &format!(r#"["STRLEN","{big}"]"#), 10).await;
        let hget = ok(&a, flavor, &format!(r#"["HGET","{h}","f"]"#), 10).await;
        delete_keys(&mut side, &[&big, &small]).await;

        for (label, result) in [("GET", &get), ("GETRANGE 0 -1", &whole_range)] {
            assert_eq!(result.columns, ["value"], "{label}");
            assert!(result.rows.is_empty(), "{}: {label}", flavor.name());
            assert!(result.truncated, "{label}");
        }
        assert_eq!(
            slice.rows,
            vec![vec![json!("x")]],
            "a small slice of it reads"
        );
        assert_eq!(
            mget.rows,
            vec![vec![json!("tiny")]],
            "only the prefix that fits"
        );
        assert!(mget.truncated);
        assert_eq!(strlen.rows, vec![vec![json!(MAX_RESULT_BYTES + 1)]]);
        assert_eq!(hget.rows, vec![vec![Value::Null]], "a missing hash is nil");
    }
}

/// Server-side evidence, not just the shaped rows: the native unbounded
/// command is never sent. `HGETALL`/`SMEMBERS` become cursor scans, and a
/// value past the byte budget gets a `STRLEN` but never a `GET`. Serial: the
/// counters are server-wide.
#[tokio::test]
#[serial_test::serial(world)]
async fn the_server_is_never_asked_for_an_unbounded_reply() {
    for flavor in Flavor::ALL {
        let a = adapter(flavor, PoolSizing::default()).await;
        let mut side = admin(flavor).await;
        let (h, set, big) = (unique_key("ch"), unique_key("cs"), unique_key("cbig"));
        let fields: Vec<String> = (0..600)
            .flat_map(|i| [format!("f{i}"), "v".to_string()])
            .collect();
        seed(&mut side, &["HSET", &h], &fields).await;
        let members: Vec<String> = (0..600).map(|i| format!("m{i}")).collect();
        seed(&mut side, &["SADD", &set], &members).await;
        admin_cmd(
            &mut side,
            &["SETRANGE", &big, &MAX_RESULT_BYTES.to_string(), "x"],
        )
        .await;

        let before = [
            calls(&mut side, "hgetall").await,
            calls(&mut side, "smembers").await,
            calls(&mut side, "get").await,
            calls(&mut side, "hscan").await,
            calls(&mut side, "sscan").await,
            calls(&mut side, "strlen").await,
        ];
        ok(&a, flavor, &format!(r#"["HGETALL","{h}"]"#), 20).await;
        ok(&a, flavor, &format!(r#"["SMEMBERS","{set}"]"#), 20).await;
        let get = ok(&a, flavor, &format!(r#"["GET","{big}"]"#), 20).await;
        let after = [
            calls(&mut side, "hgetall").await,
            calls(&mut side, "smembers").await,
            calls(&mut side, "get").await,
            calls(&mut side, "hscan").await,
            calls(&mut side, "sscan").await,
            calls(&mut side, "strlen").await,
        ];
        delete_keys(&mut side, &[&h, &set, &big]).await;

        let name = flavor.name();
        assert_eq!(after[0], before[0], "{name}: HGETALL was sent");
        assert_eq!(after[1], before[1], "{name}: SMEMBERS was sent");
        assert_eq!(after[2], before[2], "{name}: the oversized GET was sent");
        assert!(after[3] > before[3], "{name}: no HSCAN");
        assert!(after[4] > before[4], "{name}: no SSCAN");
        assert!(after[5] > before[5], "{name}: no STRLEN precheck");
        assert!(get.rows.is_empty() && get.truncated);
    }
}
