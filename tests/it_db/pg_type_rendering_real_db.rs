//! Every Postgres type in the rendering table of spec 03, round-tripped
//! through the real target: the value the server sends is the JSON the
//! agent gets, specials included (`NaN`, the infinities, `24:00:00`, a
//! `jsonb` number past `f64`). Also: `SELECT * FROM pg_class` decodes, and a
//! retryable rollback by the target is `unavailable`, not a syntax error.
//! Target: `target-db` (`bin/dev up`); the same table runs on YugabyteDB.

use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use super::pg_unnamed_statements_real_db::WireRecorder;
use crate::common::pg_target::{adapter, is_yugabyte, owner_url};
use db_mcp_gateway::audit::drain::DetachedTasks;
use db_mcp_gateway::exec::{Access, DbAdapter, ExecError, ExecQuery, QueryParam};

fn read(sql: &str, row_limit: u32) -> ExecQuery<'_> {
    ExecQuery {
        sql,
        binds: &[],
        statement_timeout_ms: Some(10_000),
        row_limit,
        access: Access::ReadOnly,
        dry_run: false,
        request_id: Uuid::new_v4(),
    }
}

/// `(SQL expression, the JSON it must come back as)`.
const CASES: &[(&str, &str)] = &[
    // numeric: the display scale, plain digits, the specials.
    ("'1.50'::numeric", r#""1.50""#),
    ("'1.5'::numeric(10,4)", r#""1.5000""#),
    (
        "'12345678901234567890.123456789'::numeric",
        r#""12345678901234567890.123456789""#,
    ),
    ("'1e-20'::numeric", r#""0.00000000000000000001""#),
    ("'1e20'::numeric", r#""100000000000000000000""#),
    ("'-0.0005'::numeric", r#""-0.0005""#),
    ("'NaN'::numeric", r#""NaN""#),
    ("'Infinity'::numeric", r#""Infinity""#),
    ("'-Infinity'::numeric", r#""-Infinity""#),
    ("'NaN'::float8", r#""NaN""#),
    ("'-Infinity'::float4", r#""-Infinity""#),
    ("1.5::float8", "1.5"),
    // json / jsonb: a number keeps its value; one an f64 cannot hold is
    // its numeral as a string.
    (
        r#"'{"a": 12345678901234567890.123, "b": 1.5, "c": 18446744073709551616, "d": 7}'::jsonb"#,
        r#"{"a": "12345678901234567890.123", "b": 1.5, "c": "18446744073709551616", "d": 7}"#,
    ),
    (r#"'[0.1, 1e300, 1.10]'::json"#, "[0.1, 1e300, 1.1]"),
    // Date and time.
    ("'24:00:00'::time", r#""24:00:00""#),
    ("'12:34:56.5+05:30'::timetz", r#""12:34:56.500+05:30""#),
    ("'infinity'::timestamptz", r#""infinity""#),
    (
        "'2024-01-02 03:04:05+00'::timestamptz",
        r#""2024-01-02T03:04:05+00:00""#,
    ),
    // Catalog types.
    (r#"'r'::"char""#, r#""r""#),
    ("26::oid", "26"),
    ("'pg_class'::regclass", "1259"),
    ("'int4'::regtype", "23"),
    ("'pg_catalog'::name", r#""pg_catalog""#),
    // Arrays.
    ("ARRAY['a', 'b']::name[]", r#"["a", "b"]"#),
    ("ARRAY[true, NULL, false]", "[true, null, false]"),
    ("ARRAY[1.5, 'NaN']::float8[]", r#"[1.5, "NaN"]"#),
    ("ARRAY[1.50, NULL]::numeric[]", r#"["1.50", null]"#),
    (
        "ARRAY['2024-01-02 03:04:05+00']::timestamptz[]",
        r#"["2024-01-02T03:04:05+00:00"]"#,
    ),
    // Text search, xml, money (`lc_monetary` decides the fraction digits;
    // the dev target runs `en_US`, two).
    ("'a fat cat'::tsvector", r#""'a' 'cat' 'fat'""#),
    ("'<a>1</a>'::xml", r#""<a>1</a>""#),
    ("'12.34'::money", r#""12.34""#),
    ("'-1234.5'::money", r#""-1234.50""#),
    ("ARRAY['1'::money]", r#"["1.00"]"#),
];

#[tokio::test]
#[serial_test::parallel(world)]
async fn every_type_renders_as_the_spec_says() {
    let adapter = adapter().await;
    let mut wrong = Vec::new();
    for (expr, want) in CASES {
        // YugabyteDB is built without libxml: any `xml` value is `0A000`.
        if is_yugabyte() && expr.ends_with("::xml") {
            continue;
        }
        let sql = format!("SELECT {expr} AS v");
        let want: Value = serde_json::from_str(want).expect("case JSON");
        match adapter.execute(read(&sql, 1)).await {
            Ok(result) if result.rows == vec![vec![want.clone()]] => {}
            Ok(result) => wrong.push(format!("{expr}: got {:?}, want {want}", result.rows)),
            Err(err) => wrong.push(format!("{expr}: {err:?}")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `relacl` is `aclitem[]`, which has no binary form: the server would
/// refuse the result in binary, so the gateway runs it with that column cast
/// to text — and only that column.
#[tokio::test]
#[serial_test::parallel(world)]
async fn select_star_from_pg_class_decodes() {
    let adapter = adapter().await;
    let result = adapter
        .execute(read(
            "SELECT * FROM pg_class WHERE relname = 'pg_class'",
            10,
        ))
        .await
        .expect("pg_class is readable");
    assert_eq!(result.rows.len(), 1, "{result:?}");
    let column = |name: &str| {
        let at = result
            .columns
            .iter()
            .position(|c| c == name)
            .unwrap_or_else(|| panic!("no {name} column in {:?}", result.columns));
        result.rows[0][at].clone()
    };
    assert_eq!(column("relname"), json!("pg_class"));
    assert_eq!(column("oid"), json!(1259));
    assert_eq!(column("relkind"), json!("r"));
    let acl = column("relacl");
    assert!(acl.is_string() || acl.is_null(), "relacl as text: {acl}");
    assert!(
        result.rows[0]
            .iter()
            .all(|cell| cell.get("unsupported_type").is_none()),
        "{result:?}"
    );

    // A misspelt function shares the SQLSTATE and still comes back as the
    // caller's own error, not as a wrapped statement's.
    let err = adapter
        .execute(read("SELECT nope_no_such_fn(1)", 1))
        .await
        .expect_err("no such function");
    let ExecError::Rejected(rejection) = err else {
        panic!("{err:?}")
    };
    assert_eq!(rejection.sqlstate(), "42883");
    assert!(
        rejection.message().contains("nope_no_such_fn"),
        "{rejection}"
    );
}

/// The driver cannot look up an internal type (`pg_node_tree`): the read is
/// described, found to need the cast, and only the text-cast statement
/// runs — its timeout is the answer.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_timeout_on_the_text_cast_attempt_is_a_timeout() {
    let adapter = adapter().await;
    let err = adapter
        .execute(ExecQuery {
            statement_timeout_ms: Some(200),
            ..read("SELECT ev_action, pg_sleep(2) FROM pg_rewrite LIMIT 1", 1)
        })
        .await
        .expect_err("pg_sleep(2) under a 200 ms budget");
    assert!(matches!(err, ExecError::Timeout), "{err:?}");
}

/// The statement was sound; the target rolled it back for a reason a retry
/// clears. That is the target's state, not the caller's SQL.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_rollback_by_the_target_is_unavailable_not_a_syntax_error() {
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let function = format!("dbmcp_retry_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {function}(code text) RETURNS int LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'retry me' USING ERRCODE = code; END $$"
    )))
    .execute(&owner)
    .await
    .expect("create raising function");

    let adapter = adapter().await;
    for code in ["40001", "40P01", "25P03"] {
        let sql = format!("SELECT {function}('{code}')");
        let outcome = adapter.execute(read(&sql, 1)).await;
        assert!(
            matches!(outcome, Err(ExecError::Unavailable)),
            "{code}: {outcome:?}"
        );
    }

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP FUNCTION {function}(text)"
    )))
    .execute(&owner)
    .await
    .expect("drop raising function");
}

/// A function whose every call leaves a session advisory lock behind — a
/// lock a rollback does not release — and returns how many calls this
/// session has made, this one included. Reads run in a read-only
/// transaction, so the lock is the one side effect that can outlive a
/// failed attempt and count it.
async fn create_call_counter(owner: &sqlx::PgPool) -> String {
    let function = format!("dbmcp_calls_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {function}() RETURNS int VOLATILE LANGUAGE plpgsql AS $$ \
         DECLARE n int; BEGIN \
         SELECT count(*) INTO n FROM pg_locks WHERE locktype = 'advisory' \
         AND pid = pg_backend_pid() AND classid = 4242 AND objsubid = 2; \
         PERFORM pg_advisory_lock(4242, n); RETURN n + 1; END $$"
    )))
    .execute(owner)
    .await
    .expect("create call counter");
    function
}

/// A read with a column the driver cannot take runs exactly once: the cast
/// is decided before the statement runs, never by retrying a failure.
/// `aclitem[]` fails only while the first row is sent — after the
/// statement's functions ran — and `pg_node_tree` while the driver looks the
/// type up.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_read_needing_the_text_cast_runs_once() {
    // YugabyteDB ships advisory locks behind a preview flag the dev stack
    // leaves off: the counter has nothing to count with there.
    if is_yugabyte() {
        return;
    }
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let calls = create_call_counter(&owner).await;
    let adapter = adapter().await;
    for sql in [
        format!("SELECT {calls}() AS calls, relacl FROM pg_class WHERE relacl IS NOT NULL LIMIT 1"),
        format!("SELECT {calls}() AS calls, ev_action FROM pg_rewrite LIMIT 1"),
    ] {
        let result = adapter
            .execute(read(&sql, 1))
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.columns[0], "calls", "{sql}: {result:?}");
        assert_eq!(
            result.rows,
            vec![vec![json!(1), result.rows[0][1].clone()]],
            "{sql}"
        );
        assert!(result.rows[0][1].is_string(), "{sql}: {result:?}");
    }
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP FUNCTION {calls}()")))
        .execute(&owner)
        .await
        .expect("drop call counter");
}

/// Observe the body running on PostgreSQL and count its Executes on the wire,
/// where rollback and session cleanup cannot erase evidence of a retry.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_cancelled_read_runs_once() {
    if is_yugabyte() {
        return;
    }
    crate::common::pg_target::ensure_read_role().await;
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let wire = WireRecorder::start().await;
    let detached = DetachedTasks::new();
    let adapter = wire.adapter(1, detached.clone()).await;
    let sql = "SELECT relacl, pg_sleep(120) FROM pg_class \
               WHERE oid = 'pg_catalog.pg_class'::regclass \
               AND 'read-once-probe' = 'read-once-probe'";
    let victim = ExecQuery {
        statement_timeout_ms: Some(30_000),
        ..read(sql, 1)
    };
    let request_id = victim.request_id;
    assert_eq!(wire.read_once_executions(), (0, 0));
    let (cancelled, ()) = tokio::join!(adapter.execute(victim), async {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let executing: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT FROM pg_stat_activity WHERE application_name LIKE $1 \
                     AND wait_event = 'PgSleep')",
                )
                .bind(format!("dbmcp-{}-%", request_id.simple()))
                .fetch_one(&owner)
                .await
                .expect("observe the body from another session");
                if executing {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("text-cast read reached its executing body");
        assert_eq!(wire.read_once_executions(), (1, 1));
        assert!(adapter.cancel_request(request_id).await.expect("cancel runs"));
    });
    assert!(
        matches!(cancelled, Err(ExecError::Cancelled)),
        "{cancelled:?}"
    );

    let sql = "SELECT relacl FROM pg_class WHERE oid = 'pg_catalog.pg_class'::regclass \
               AND 'read-once-probe' = 'read-once-probe'";
    let again = adapter
        .execute(read(sql, 1))
        .await
        .unwrap_or_else(|err| panic!("same read after cancel: {err:?}"));
    let expected: String = sqlx::query_scalar(
        "SELECT relacl::text FROM pg_class WHERE oid = 'pg_catalog.pg_class'::regclass",
    )
    .fetch_one(&owner)
        .await
        .expect("read the expected ACL directly");
    assert_eq!(again.rows, vec![vec![json!(expected)]]);
    assert_eq!(again.column_types, ["TEXT"]);
    detached
        .drain(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(wire.read_once_executions(), (2, 2));
}

/// A plain read's functions run once too, though its text is parsed twice.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_plain_read_runs_once() {
    // No advisory locks to count with (see above).
    if is_yugabyte() {
        return;
    }
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let calls = create_call_counter(&owner).await;
    let adapter = adapter().await;
    for (sql, params) in [
        (format!("SELECT {calls}()"), vec![]),
        (
            format!("SELECT {calls}() WHERE $1 = 1"),
            vec![QueryParam::Int(1)],
        ),
        // The first call is discarded; the count is the second's.
        (
            format!("SELECT {calls}() FROM generate_series(1, 2) OFFSET 1"),
            vec![],
        ),
    ] {
        let want = if sql.contains("OFFSET") { 2 } else { 1 };
        let result = adapter
            .execute_with_params(read(&sql, 1), &params)
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.rows, vec![vec![json!(want)]], "{sql}");
    }
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP FUNCTION {calls}()")))
        .execute(&owner)
        .await
        .expect("drop call counter");
}

/// The cast is decided from the statement's description with the caller's
/// params, never from a run with every param NULL: `array_fill` refuses a
/// NULL dimension while the statement is planned. A plain `LIMIT $1` takes
/// the cast too.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_text_cast_read_keeps_params_a_null_would_break() {
    let adapter = adapter().await;
    for sql in [
        "SELECT relname, relacl FROM pg_class WHERE relacl IS NOT NULL ORDER BY oid LIMIT $1",
        "SELECT relname, relacl FROM pg_class WHERE relacl IS NOT NULL ORDER BY oid \
         LIMIT array_length(array_fill(0, ARRAY[$1::int]), 1)",
        "SELECT relname, ev_action FROM pg_class JOIN pg_rewrite ON ev_class = pg_class.oid \
         ORDER BY pg_rewrite.oid LIMIT array_length(array_fill(0, ARRAY[$1::int]), 1)",
    ] {
        let result = adapter
            .execute_with_params(read(sql, 10), &[QueryParam::Int(1)])
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.rows.len(), 1, "{sql}: {result:?}");
        assert!(result.rows[0][1].is_string(), "{sql}: {result:?}");
    }
}

/// A zero-row read needing the cast still names its columns, the cast one
/// as `text`.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_zero_row_text_cast_read_keeps_its_columns() {
    let adapter = adapter().await;
    let result = adapter
        .execute(read("SELECT oid, relacl FROM pg_class WHERE false", 1))
        .await
        .expect("zero-row read");
    assert!(result.rows.is_empty(), "{result:?}");
    assert_eq!(result.columns, vec!["oid", "relacl"]);
    assert_eq!(result.column_types, vec!["OID", "TEXT"]);
}

/// The caller's text is nested only once it stands as one statement of its
/// own: every shape a read can have is taken, by both routes to the text
/// cast, and a second statement, or a parenthesis that would close the
/// wrapper's, is refused.
#[tokio::test]
#[serial_test::parallel(world)]
async fn only_a_statement_of_its_own_is_nested() {
    let a = adapter().await;
    for sql in [
        "TABLE pg_rewrite",
        "(SELECT ev_action FROM pg_rewrite)",
        "WITH r AS (SELECT ev_action FROM pg_rewrite) SELECT * FROM r -- c",
        "SELECT ev_action FROM pg_rewrite WHERE ev_type <> ';' ORDER BY oid DESC;",
        "SELECT relacl FROM pg_class UNION ALL (SELECT relacl FROM pg_class LIMIT 1)",
        "VALUES ((SELECT relacl FROM pg_class ORDER BY oid LIMIT 1))",
    ] {
        let result = a
            .execute(read(sql, 1))
            .await
            .unwrap_or_else(|err| panic!("{sql}: {err:?}"));
        assert_eq!(result.rows.len(), 1, "{sql}");
    }
    let params = [QueryParam::Null, QueryParam::Int(1)];
    let untyped = "SELECT ev_action FROM pg_rewrite WHERE $1::text IS NULL LIMIT $2";
    let result = a.execute_with_params(read(untyped, 10), &params).await;
    assert_eq!(result.expect("a NULL's type is inferred").rows.len(), 1);

    for sql in [
        "SELECT relacl FROM pg_class; SELECT 1",
        "SELECT ev_action FROM pg_rewrite; SELECT 1",
        "SELECT relacl FROM pg_class) AS q(c1), (SELECT 1",
        "SELECT ev_action FROM pg_rewrite) AS s, (SELECT 1",
    ] {
        let outcome = a.execute(read(sql, 1)).await;
        let Err(ExecError::Rejected(rejection)) = outcome else {
            panic!("{sql}: {outcome:?}")
        };
        assert_eq!(rejection.sqlstate(), "42601", "{sql}");
    }
}

/// The read every fallback test runs: `ev_action` sends it through the
/// cursor description, whose planning folds the immutable call — the
/// fallback is what is slow, not the read. Returns `(function, sql)`.
async fn slow_fallback(owner: &sqlx::PgPool) -> (String, String) {
    let function = format!("dbmcp_slow_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION {function}(s int) RETURNS int IMMUTABLE LANGUAGE plpgsql AS \
         $$ BEGIN PERFORM pg_sleep(s); RETURN s; END $$"
    )))
    .execute(owner)
    .await
    .expect("create slow function");
    let sql = format!("SELECT {function}(8), ev_action FROM pg_rewrite LIMIT 1");
    (function, sql)
}

/// A timeout, a cancel or a lost connection while the fallback describes a
/// read is reported as itself, never as the type lookup that led there.
#[tokio::test]
#[serial_test::parallel(world)]
async fn an_operational_failure_while_describing_is_reported_as_itself() {
    let owner = PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url())
        .await
        .expect("target-db reachable; run `bin/dev up`");
    let (function, sql) = slow_fallback(&owner).await;
    let adapter = adapter().await;

    let timed_out = adapter
        .execute(ExecQuery {
            statement_timeout_ms: Some(300),
            ..read(&sql, 1)
        })
        .await;

    let victim = read(&sql, 1);
    let request_id = victim.request_id;
    let (cancelled, ()) = tokio::join!(adapter.execute(victim), async {
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if adapter
                .cancel_request(request_id)
                .await
                .expect("cancel runs")
            {
                return;
            }
        }
        panic!("the fallback was never cancelled");
    });

    let victim = read(&sql, 1);
    let tag = format!("dbmcp-{}-%", victim.request_id.simple());
    let (lost, ()) = tokio::join!(adapter.execute(victim), async {
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let killed: Vec<bool> = sqlx::query_scalar(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE application_name LIKE $1 AND query LIKE 'DECLARE%'",
            )
            .bind(&tag)
            .fetch_all(&owner)
            .await
            .expect("terminate runs");
            if killed.contains(&true) {
                return;
            }
        }
        panic!("the fallback was never seen");
    });

    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP FUNCTION {function}(int)"
    )))
    .execute(&owner)
    .await
    .expect("drop slow function");
    assert!(
        matches!(timed_out, Err(ExecError::Timeout)),
        "{timed_out:?}"
    );
    assert!(
        matches!(cancelled, Err(ExecError::Cancelled)),
        "{cancelled:?}"
    );
    assert!(matches!(lost, Err(ExecError::Unavailable)), "{lost:?}");
}

/// What the target refuses while the fallback plans the caller's statement
/// is the caller's error, with its own code.
#[tokio::test]
#[serial_test::parallel(world)]
async fn a_refusal_while_describing_keeps_its_sqlstate() {
    let adapter = adapter().await;
    let err = adapter
        .execute(read("SELECT 1 / 0, ev_action FROM pg_rewrite LIMIT 1", 1))
        .await
        .expect_err("division by zero");
    let ExecError::Rejected(rejection) = err else {
        panic!("{err:?}")
    };
    assert_eq!(rejection.sqlstate(), "22012");
    assert_eq!(rejection.position(), None);
}
