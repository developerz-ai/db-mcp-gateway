//! The guard answers for the whole text: the statement must be read to its
//! end, and a name counts wherever it is written.

use super::*;
use crate::exec::sql_guard::pg_scan;
use crate::exec::sql_guard::tokens::check_tokens;

const ACCESSES: [Access; 2] = [Access::ReadOnly, Access::ReadWrite];

#[test]
fn a_statement_must_be_read_to_its_end() {
    for sql in [
        "SELECT 1 END",
        "SELECT 1 end",
        "SELECT 1 /* c */ End -- c\n",
        "SELECT 1 END, 2",
        "SELECT 1 END, pg_notify('c', 'p')",
        "SELECT 1 END, set_config('a.b', 'c', false)",
        "SELECT a END FROM t FOR UPDATE",
        "SELECT a END FROM t FOR NO KEY UPDATE",
        "SELECT 1 END INTO t2",
        "SELECT 1 END FROM cron.job",
        "SELECT 1 END; SELECT 2",
        "SELECT 1 END END",
        "EXPLAIN SELECT 1 END, 2",
        "VALUES (1) END",
        "WITH w AS (SELECT 1) SELECT * FROM w END",
        "INSERT INTO t VALUES (1) END",
        "INSERT INTO t VALUES (1) RETURNING a END, pg_notify('c', 'p')",
        "UPDATE t SET a = 1 RETURNING a END",
        "DELETE FROM t WHERE a END",
    ] {
        for access in ACCESSES {
            let got = check_sql(sql, access);
            let stopped = matches!(got, Err(GuardError::Parse(Some(_))));
            assert!(stopped, "{access:?} `{sql}`: {got:?}");
        }
    }
}

#[test]
fn the_error_is_where_reading_stopped() {
    let at = |line, column| Err(GuardError::Parse(Some(SqlLocation { line, column })));
    assert_eq!(is_read_only("SELECT 1 END, 2"), at(1, 10));
    assert_eq!(is_read_only("SELECT a\n  END\nFROM t"), at(2, 3));
}

#[test]
fn treat_is_a_call_of_the_name_it_converts_to() {
    for sql in [
        "SELECT TREAT(1 AS pg_advisory_lock)",
        "SELECT treat ( 'f' AS \"lo_creat\")",
        "SELECT 1 WHERE TREAT(a AS int) > 1",
        "SELECT * FROM TREAT(1 AS int)",
    ] {
        for access in ACCESSES {
            let got = check_sql(sql, access);
            assert_eq!(got, Err(GuardError::DeniedFunction("treat")), "`{sql}`");
        }
    }
}

#[test]
fn clauses_keep_their_meaning_after_a_label() {
    for (sql, want) in [
        ("SELECT a AND FOR UPDATE", GuardError::Locking),
        ("SELECT interval FOR SHARE", GuardError::Locking),
        ("SELECT a AND FOR SHARE", GuardError::Locking),
        ("SELECT interval INTO t2 FROM t", GuardError::SelectInto),
        ("SELECT a OR INTO t2", GuardError::SelectInto),
    ] {
        for access in ACCESSES {
            assert_eq!(check_sql(sql, access), Err(want.clone()), "`{sql}`");
        }
    }
}

/// The token rules alone, without the tree that repeats them.
#[test]
fn token_rules_hold_whatever_the_tree_holds() {
    let check = |sql: &str| check_tokens(sql, &pg_scan::scan(sql).expect("scans"));
    for (sql, name) in [
        ("x pg_notify('c', 'p')", "pg_notify"),
        ("x PG_NOTIFY /* c */ (1)", "pg_notify"),
        ("x \"pg_notify\"(1)", "pg_notify"),
        ("x pg_catalog.pg_notify(1)", "pg_notify"),
        ("x \"pg_catalog\" . \"lo_creat\" (1)", "lo_*"),
        ("x, pg_ls_waldir((1))", "pg_ls_*"),
        ("x AS b, pg_notify(1)", "pg_notify"),
        ("x () pg_notify(1)", "pg_notify"),
        ("pg_notify(1)", "pg_notify"),
    ] {
        assert_eq!(check(sql), Err(GuardError::DeniedFunction(name)), "{sql}");
    }
    for sql in [
        "x FOR UPDATE",
        "x for share",
        "x FOR NO KEY UPDATE",
        "x FOR/**/KEY SHARE",
    ] {
        assert_eq!(check(sql), Err(GuardError::Locking), "{sql}");
    }
    for sql in ["INTO t", "x INTO t", "x () INTO t", "x 'insert' INTO t"] {
        assert_eq!(check(sql), Err(GuardError::SelectInto), "{sql}");
    }
    for sql in [
        "'pg_notify(1)'",
        "-- pg_notify(1)\n x",
        "$$ FOR UPDATE $$",
        "x \"FOR\" UPDATE",
        "x \"into\" t",
    ] {
        assert_eq!(check(sql), Ok(()), "{sql}");
    }
}

#[test]
fn table_commands_name_a_relation() {
    for sql in [
        "SELECT * FROM (TABLE cron.job) x",
        "SELECT 1 UNION ALL TABLE \"cron\".\"job\"",
        "SELECT * FROM (TABLE cron.job UNION SELECT 1) x",
        "SELECT 1 UNION (SELECT 2 EXCEPT TABLE cron.job)",
        "WITH w AS (TABLE CRON.job) SELECT * FROM w",
        "SELECT EXISTS (TABLE cron.job), ARRAY(TABLE cron.job)",
        "EXPLAIN SELECT * FROM (TABLE cron.job) x",
        "INSERT INTO t SELECT * FROM (TABLE cron.job) x",
        "UPDATE t SET a = (SELECT b FROM (TABLE cron.job) j)",
        "DELETE FROM t WHERE a IN (SELECT 1 UNION TABLE cron.job)",
    ] {
        let got = check_sql(sql, Access::ReadWrite);
        assert_eq!(got, Err(GuardError::DeniedRelation("cron.*")), "`{sql}`");
    }
    let sql = "SELECT * FROM (TABLE pg_stat_activity) x";
    rejected(sql, GuardError::DeniedRelation("pg_stat_activity"));
    ok("SELECT * FROM (TABLE app.job) x UNION TABLE t");
}

/// Names that are also keywords or on the denylist, as labels, aliases,
/// columns and tables.
#[test]
fn labels_aliases_and_columns_stay_admitted() {
    for sql in [
        "SELECT a AS end FROM t",
        "SELECT a AS \"end\", b AS \"END\" FROM t",
        "SELECT t.end FROM t",
        "SELECT t.\"end\" FROM t",
        "SELECT CASE WHEN a THEN 1 END FROM t",
        "SELECT CASE a WHEN 1 THEN 2 ELSE CASE WHEN b THEN 3 END END AS end FROM t",
        "SELECT CASE WHEN a THEN 1 END, CASE WHEN b THEN 1 END x FROM t",
        "SELECT sum(CASE WHEN a THEN 1 ELSE 0 END) FROM t GROUP BY CASE WHEN b THEN 1 END",
        "SELECT notify, listen, schedule, invoke FROM t",
        "SELECT a AS pg_notify, b AS schedule FROM t",
        "SELECT schedule.day, invoke.x FROM schedule JOIN invoke USING (id)",
        "SELECT * FROM schedule WHERE (a) IN (1)",
        "SELECT * FROM (VALUES (1)) AS schedule(day)",
        "SELECT * FROM generate_series(1, 3) AS lo_n(x)",
        "WITH schedule(day) AS (SELECT 1) SELECT * FROM schedule",
        "WITH RECURSIVE schedule(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM schedule) SELECT * FROM schedule",
        "SELECT treat, t.treat FROM t",
        "SELECT substring(a FROM 1 FOR 2), overlay(a PLACING b FROM 1 FOR 2) FROM t",
        "SELECT substring(a FOR 2) FROM t",
        "SELECT a AS into, t.into FROM t",
        "SELECT a AS for, key, share, update FROM t",
        "SELECT 'x END, pg_notify(1)', $$ FOR UPDATE INTO $$ -- END, pg_notify(1)",
        "SELECT 1;",
        "SELECT 1 ; ; -- done",
    ] {
        for access in ACCESSES {
            assert_eq!(check_sql(sql, access), Ok(()), "{access:?} `{sql}`");
        }
    }
    for sql in [
        "INSERT INTO schedule (a, b) VALUES (1, 2)",
        "INSERT INTO app.schedule (a) SELECT 1",
        "INSERT INTO \"schedule\"(a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 1",
        "INSERT INTO lo_orders (lo_revenue) VALUES (1) RETURNING lo_revenue AS end",
        "UPDATE schedule SET invoke = 1 WHERE a = (SELECT 1)",
        "DELETE FROM schedule WHERE a IN (SELECT 1)",
    ] {
        assert_eq!(check_sql(sql, Access::ReadWrite), Ok(()), "`{sql}`");
    }
}
