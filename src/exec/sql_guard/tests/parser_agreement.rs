use super::*;
use crate::exec::sql_guard::agreement::check_agreement;
use crate::exec::sql_guard::calls::Calls;

// --- The full guard: both parsers must read the statement alike ---

/// Spellings Postgres's grammar turns into plain calls that sqlparser
/// models as their own expressions or table factors: both readings name
/// the same functions, so they stay admitted.
#[test]
fn calls_postgres_spells_differently_stay_admitted() {
    for sql in [
        "SELECT UPPER('a'), Count(*), Pg_Catalog.Lower('A'), CEIL(1.5)",
        "SELECT ceil(1.5), ceiling(1.5), floor(1.5)",
        "SELECT substring('abc', 1, 2), substring('abc' from 1 for 2)",
        "SELECT substr('abc', 1), substr('abc', 1, 2)",
        "SELECT position('a' in 'abc'), overlay('abc' placing 'x' from 1)",
        "SELECT trim(both 'x' from 'xax'), ltrim('a'), btrim('a')",
        "SELECT extract(year from now()), now() AT TIME ZONE 'UTC'",
        "SELECT coalesce(1, 2), nullif(1, 2), greatest(1, 2), least(1, 2)",
        "SELECT current_timestamp, current_user, system_user",
        "SELECT x FROM t WHERE x SIMILAR TO 'a%' OR x LIKE 'a!%' ESCAPE '!'",
        "SELECT * FROM unnest(ARRAY[1]) WITH ORDINALITY",
        "SELECT \"Upper\"(x), pg_catalog.upper('a') FROM t",
        "SELECT count(*), sum(x) FILTER (WHERE x > 1), row_number() OVER () FROM t",
        "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY x) FROM t",
        "SELECT f(x => 1), (x).y, a.b.c.d FROM t",
        "EXPLAIN (FORMAT JSON) SELECT upper('a')",
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT * FROM r",
        "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3",
        "VALUES (1), (2)",
        "SELECT $1::int, $2",
        ";SELECT 1;;",
    ] {
        ok(sql);
    }
    for sql in [
        "INSERT INTO t VALUES (1) RETURNING upper(x)",
        "UPDATE t SET a = lower(b) WHERE c = 1",
        "DELETE FROM t USING u WHERE t.id = u.id",
        "INSERT INTO t SELECT * FROM u ON CONFLICT (id) DO UPDATE SET a = excluded.a",
        "EXPLAIN INSERT INTO t VALUES (1)",
    ] {
        assert_eq!(check_sql(sql, Access::ReadWrite), Ok(()), "for `{sql}`");
    }
}

/// Syntax sqlparser accepts from other dialects but Postgres's grammar
/// does not: refused at the guard instead of failing at the target.
#[test]
fn syntax_only_sqlparser_reads_is_refused() {
    for sql in [
        "SELECT x FROM t QUALIFY x = 1",
        "SELECT TOP 1 x FROM t",
        "SELECT x FROM t GROUP BY ALL",
        "SELECT x FROM t FOR JSON PATH",
        "SELECT [1, 2]",
        "SELECT x FROM t CONNECT BY PRIOR a = b",
    ] {
        rejected(sql, GuardError::ParserDisagreement("syntax"));
    }
}

// --- The check on its own: a reading that is not Postgres's is refused ---

fn reading(kind: Kind, calls: &[&str]) -> Reading {
    Reading {
        explained: false,
        kind,
        calls: Calls::of(calls),
    }
}

#[test]
fn agreeing_reading_passes() {
    let upper: &[&str] = &["upper"];
    assert_eq!(
        check_agreement("SELECT upper(x) FROM t", &reading(Kind::Select, upper)),
        Ok(())
    );
}

#[test]
fn statement_count_must_be_one() {
    assert_eq!(
        check_agreement("SELECT 1; SELECT 2", &reading(Kind::Select, &[])),
        Err(GuardError::ParserDisagreement("statement count"))
    );
}

#[test]
fn statement_kind_must_match() {
    let kind = Err(GuardError::ParserDisagreement("statement kind"));
    let select = reading(Kind::Select, &[]);
    for sql in [
        "INSERT INTO t VALUES (1)",
        "EXPLAIN SELECT 1",
        "WITH w AS (DELETE FROM t RETURNING 1) SELECT * FROM w",
        "SELECT 1 FROM t FOR UPDATE",
        "SELECT 1 INTO t2",
    ] {
        assert_eq!(check_agreement(sql, &select), kind, "for `{sql}`");
    }
    assert_eq!(
        check_agreement("SELECT 1", &reading(Kind::Delete, &[])),
        kind
    );
    for (read, sql) in [
        (Kind::Insert, "DELETE FROM t"),
        (Kind::Update, "INSERT INTO t VALUES (1)"),
        (Kind::Delete, "UPDATE t SET a = 1"),
    ] {
        assert_eq!(
            check_agreement(sql, &reading(read, &[])),
            kind,
            "for `{sql}`"
        );
    }
    // A write's own CTE may not write a second time.
    assert_eq!(
        check_agreement(
            "WITH w AS (DELETE FROM u RETURNING 1) INSERT INTO t SELECT * FROM w",
            &reading(Kind::Insert, &[])
        ),
        kind
    );
}

#[test]
fn a_call_only_postgres_sees_is_refused() {
    let calls = Err(GuardError::ParserDisagreement("function calls"));
    for sql in [
        "SELECT md5('x')",
        "SELECT 1 FROM generate_series(1, 3)",
        "SELECT upper(lower(md5('x')))",
    ] {
        assert_eq!(
            check_agreement(sql, &reading(Kind::Select, &[])),
            calls,
            "for `{sql}`"
        );
    }
    // A quoted name keeps its case in Postgres: `"MD5"` is not `md5`.
    let md5: &[&str] = &["md5"];
    assert_eq!(
        check_agreement("SELECT \"MD5\"('x')", &reading(Kind::Select, md5)),
        calls
    );
}

/// The denylist holds against Postgres's own calls and relations too.
#[test]
fn denylist_applies_to_postgres_reading() {
    let all: &[&str] = &["pg_notify", "lo_creat", "job"];
    let select = reading(Kind::Select, all);
    for (sql, want) in [
        (
            "SELECT pg_notify('a', 'b')",
            GuardError::DeniedFunction("pg_notify"),
        ),
        ("SELECT lo_creat(1)", GuardError::DeniedFunction("lo_*")),
        ("SELECT cron.job()", GuardError::DeniedFunction("cron.*")),
        (
            "SELECT * FROM pg_stat_activity",
            GuardError::DeniedRelation("pg_stat_activity"),
        ),
        (
            "SELECT * FROM cron.task",
            GuardError::DeniedRelation("cron.*"),
        ),
        ("EXPLAIN (ANALYSE) SELECT 1", GuardError::ExplainAnalyze),
    ] {
        assert_eq!(check_agreement(sql, &select), Err(want), "for `{sql}`");
    }
}

/// A write's target and a name in attribute notation meet the denylists on
/// Postgres's reading alone, as a read relation and a call do.
#[test]
fn every_position_of_a_name_meets_the_denylists() {
    let cron = GuardError::DeniedRelation("cron.*");
    for (kind, sql, want) in [
        (
            Kind::Insert,
            "INSERT INTO cron.job VALUES (1)",
            cron.clone(),
        ),
        (Kind::Update, "UPDATE \"cron\".job SET a = 1", cron.clone()),
        (Kind::Update, "UPDATE ONLY cron.job SET a = 1", cron.clone()),
        (Kind::Delete, "DELETE FROM ONLY (cron.job)", cron.clone()),
        (Kind::Delete, "DELETE FROM t USING cron.job", cron.clone()),
        (Kind::Delete, "DELETE FROM db.cron.job", cron.clone()),
        (Kind::Delete, "DELETE FROM cron.s.job", cron.clone()),
        (Kind::Select, "SELECT * FROM (TABLE cron.job) x", cron),
        (
            Kind::Update,
            "UPDATE pg_settings SET setting = 1",
            GuardError::DeniedFunction("set_config"),
        ),
        (
            Kind::Select,
            "SELECT (x).pg_notify FROM t",
            GuardError::DeniedFunction("pg_notify"),
        ),
        (
            Kind::Select,
            "SELECT t.c.pg_notify FROM t",
            GuardError::DeniedFunction("pg_notify"),
        ),
        (
            Kind::Select,
            "SELECT t.http FROM t",
            GuardError::DeniedFunction("http"),
        ),
    ] {
        let got = check_agreement(sql, &reading(kind, &[]));
        assert_eq!(got, Err(want), "for `{sql}`");
    }
    // An exact name no row can be passed to is an ordinary column.
    let column = check_agreement("SELECT t.pg_notify FROM t", &reading(Kind::Select, &[]));
    assert_eq!(column, Ok(()));
}

/// Statements other kinds of statement wrap or hold are a kind disagreement.
#[test]
fn a_statement_of_another_kind_is_refused() {
    for sql in [
        "CREATE TABLE t AS SELECT 1",
        "EXPLAIN CREATE TABLE t AS SELECT 1",
        "COPY t TO STDOUT",
        "MERGE INTO t USING u ON true WHEN MATCHED THEN DELETE",
        "WITH m AS (MERGE INTO t USING u ON true WHEN MATCHED THEN DELETE RETURNING 1) SELECT 1",
        "SELECT * FROM (SELECT 1 FROM t FOR SHARE) x",
        "SET x = 1",
        "CALL f()",
    ] {
        let got = check_agreement(sql, &reading(Kind::Select, &[]));
        assert_eq!(
            got,
            Err(GuardError::ParserDisagreement("statement kind")),
            "for `{sql}`"
        );
    }
}

/// Queries real clients write stay admitted.
#[test]
fn realistic_queries_stay_admitted() {
    for sql in [
        "SELECT a.id, count(*) FROM a LEFT JOIN b USING (id) GROUP BY GROUPING SETS ((a.id), ROLLUP (a.x), ()) HAVING count(*) > 1 ORDER BY 2 DESC NULLS LAST LIMIT 5 OFFSET 2",
        "SELECT sum(x) OVER w, lag(x) OVER (PARTITION BY a ORDER BY b ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t WINDOW w AS (PARTITION BY a)",
        "SELECT * FROM t, LATERAL (SELECT max(u.x) FROM u WHERE u.id = t.id) m",
        "SELECT * FROM t CROSS JOIN LATERAL jsonb_array_elements(t.j -> 'a') AS e(v)",
        "SELECT j ->> 'a', j #> '{a,b}', j #>> '{a}', j @> '{}'::jsonb, j ? 'a', j @? '$.a' FROM t",
        "SELECT json_build_object('a', 1), jsonb_agg(x ORDER BY y), to_jsonb(t) FROM t",
        "WITH RECURSIVE r AS (SELECT id FROM t WHERE p IS NULL UNION ALL SELECT t.id FROM t JOIN r ON t.p = r.id) SELECT * FROM r",
        "WITH a AS MATERIALIZED (SELECT 1 AS x), b AS NOT MATERIALIZED (SELECT * FROM a) SELECT * FROM b",
        "SELECT date_trunc('day', ts AT TIME ZONE 'UTC'), extract(epoch FROM ts), ts::date, interval '1 day' FROM t",
        "SELECT DISTINCT ON (a) a, b FROM t ORDER BY a, b",
        "SELECT CASE WHEN a THEN 1 ELSE 2 END, coalesce(a, b), nullif(a, b), greatest(a, b), least(a, b) FROM t",
        "SELECT x = ANY (ARRAY[1, 2]), x IN (SELECT 1), EXISTS (SELECT 1), ARRAY(SELECT 1), (SELECT 1) FROM t",
        "SELECT string_agg(DISTINCT x, ',' ORDER BY x) FILTER (WHERE x <> '') FROM t",
        "SELECT mode() WITHIN GROUP (ORDER BY x), percentile_disc(0.9) WITHIN GROUP (ORDER BY x) FROM t",
        "SELECT substring(x, 1, 2), substr(x, 1), trim(x), trim(LEADING 'a' FROM x), overlay(x PLACING 'b' FROM 1), position('a' IN x), x || 'a' FROM t",
        "SELECT a[1], a[1:2], (r).f, (r).f[1], t.* FROM t",
        "SELECT yb_hash_code(id) FROM t WHERE yb_hash_code(id) BETWEEN 0 AND 100",
        "SELECT * FROM t TABLESAMPLE SYSTEM (1)",
        "SELECT * FROM generate_series(1, 10) WITH ORDINALITY AS g(v, n)",
        "SELECT x COLLATE \"C\" FROM t WHERE x ILIKE 'a%' AND x ~ 'b' AND x IS DISTINCT FROM y AND b IS NOT TRUE",
        "SELECT * FROM (VALUES (1, 'a'), (2, 'b')) v(id, n)",
        "SELECT * FROM t FETCH FIRST 3 ROWS ONLY",
        "SELECT 1 EXCEPT (SELECT 2 INTERSECT SELECT 3)",
        "EXPLAIN (VERBOSE, FORMAT JSON) SELECT * FROM t",
    ] {
        ok(sql);
    }
    for sql in [
        "INSERT INTO t (a, b) VALUES (1, DEFAULT) ON CONFLICT (a) DO NOTHING RETURNING *",
        "INSERT INTO t (a) SELECT x FROM u ON CONFLICT (a) DO UPDATE SET b = EXCLUDED.b WHERE t.b <> EXCLUDED.b",
        "UPDATE t SET (a, b) = (1, 2) FROM u WHERE t.id = u.id RETURNING t.a",
        "DELETE FROM t WHERE id IN (SELECT id FROM u) RETURNING id",
    ] {
        assert_eq!(check_sql(sql, Access::ReadWrite), Ok(()), "for `{sql}`");
    }
}
