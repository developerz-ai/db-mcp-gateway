//! Every Postgres type in the rendering table of spec 03, round-tripped
//! through the real target: the value the server sends is the JSON the
//! agent gets, specials included (`NaN`, the infinities, `24:00:00`, a
//! `jsonb` number past `f64`). Also: `SELECT * FROM pg_class` decodes, and a
//! retryable rollback by the target is `unavailable`, not a syntax error.
//! Target: `target-db` (`bin/dev up`); the same table runs on YugabyteDB.

use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::common::pg_target::{adapter, is_yugabyte, owner_url};
use db_mcp_gateway::exec::{Access, DbAdapter, ExecError, ExecQuery};

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

/// `relacl` is `aclitem[]`, which has no binary form: the server refuses
/// the whole result in binary, so the gateway asks again with that column
/// cast to text — and only that column.
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
