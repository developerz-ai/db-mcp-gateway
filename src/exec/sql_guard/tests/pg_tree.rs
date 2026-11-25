//! The wire walk: every message Postgres's tree holds, none missed, and no
//! damaged bytes read as a tree.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;

use super::oracle;
use crate::exec::sql_guard::pg_tree::schema::{self, NodeType, number};
use crate::exec::sql_guard::pg_tree::wire::walk;
use crate::exec::sql_guard::pg_tree::{Unreadable, parse};

/// At least one statement per message type the schema names.
pub(super) const COVER: &[&str] = &[
    "EXPLAIN (VERBOSE, COSTS false, FORMAT json, WAL 1, SETTINGS 1.5) SELECT 1",
    "SELECT a, $1, *, t.*, 1, 1.5, 'x', true, null, B'01', X'1F', E'\\n' FROM t AS t(a, b)",
    "SELECT GROUPING(a), count(*) FROM t GROUP BY GROUPING SETS ((a), ROLLUP(a, b), CUBE(a), ())",
    "SELECT f(a => 1, b := 2), f(VARIADIC ARRAY[1,2]), f(DISTINCT a ORDER BY b DESC NULLS LAST) FILTER (WHERE a) OVER w FROM t WINDOW w AS (PARTITION BY a ORDER BY b ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY a) FROM t",
    "SELECT NOT a AND b OR c, EXISTS (SELECT 1), a = ANY (SELECT 1), ARRAY(SELECT 1), a IN (SELECT 1), a IN (1, 2), (SELECT 1)",
    "SELECT CASE a WHEN 1 THEN 2 ELSE 3 END, ROW(1, 2), (1, 2), COALESCE(a, b), GREATEST(a, b), NULLIF(a, b)",
    "SELECT XMLELEMENT(NAME a, XMLATTRIBUTES(b AS c), d), XMLFOREST(a AS b), XMLSERIALIZE(CONTENT x AS text), x IS DOCUMENT, XMLPARSE(CONTENT x), XMLROOT(x, VERSION '1.0'), XMLPI(NAME a), XMLCONCAT(a, b), XMLEXISTS('a' PASSING x)",
    "SELECT a IS NULL, a IS NOT TRUE, a IS UNKNOWN, a IS DISTINCT FROM b, a BETWEEN 1 AND 2, a LIKE 'x' ESCAPE 'y', a SIMILAR TO 'b', a ~ 'b', a OPERATOR(pg_catalog.+) b, a COLLATE \"C\", a::int[], CAST(a AS numeric(10, 2)), a[1], a[1:2], (a).b[2].c, (a).*, interval '1' day, date '2020-01-01'",
    "SELECT current_date, current_timestamp(3), current_user, localtime, session_user, EXTRACT(year FROM a), a AT TIME ZONE 'x', a AT LOCAL, SUBSTRING(a FROM 1 FOR 2), POSITION(a IN b), OVERLAY(a PLACING b FROM 1), TRIM(BOTH a FROM b), NORMALIZE(a, NFC), a IS NFC NORMALIZED, (a, b) OVERLAPS (c, d), CEIL(1), COLLATION FOR (a), CAST(a AS char varying)",
    "SELECT * FROM a JOIN b USING (x) AS j LEFT JOIN LATERAL (SELECT 1) s ON true NATURAL JOIN c CROSS JOIN d, ONLY e, f *, (g JOIN h ON true) AS k",
    "SELECT * FROM f(1) WITH ORDINALITY AS t(a, b), ROWS FROM (f(1), g(2) AS (a int, b text COLLATE \"C\")) AS r, unnest(a, b) u, t TABLESAMPLE bernoulli (10) REPEATABLE (1)",
    "SELECT * FROM XMLTABLE(XMLNAMESPACES('a' AS b), '/x' PASSING d COLUMNS a int PATH 'p' DEFAULT 1 NOT NULL, o FOR ORDINALITY)",
    "SELECT * FROM JSON_TABLE(j, '$.a' AS p PASSING 1 AS x COLUMNS (id FOR ORDINALITY, a int PATH '$.b' DEFAULT 1 ON EMPTY ERROR ON ERROR, b text FORMAT JSON PATH '$', c boolean EXISTS PATH '$', NESTED PATH '$.n' AS n COLUMNS (d int))) jt",
    "SELECT JSON_OBJECT('a': 1, 'b' VALUE 2 ABSENT ON NULL WITH UNIQUE KEYS RETURNING jsonb FORMAT JSON), JSON_ARRAY(1, 2 NULL ON NULL RETURNING text), JSON_ARRAY(SELECT 1), JSON_OBJECTAGG(k: v), JSON_ARRAYAGG(a ORDER BY b RETURNING jsonb) FILTER (WHERE a), JSON('{}' FORMAT JSON ENCODING UTF8), JSON_SCALAR(1), JSON_SERIALIZE(a RETURNING text), a IS JSON OBJECT WITH UNIQUE KEYS",
    "SELECT JSON_VALUE(a, '$' PASSING 1 AS x RETURNING int DEFAULT 1 ON EMPTY ERROR ON ERROR), JSON_QUERY(a, '$' WITH WRAPPER OMIT QUOTES), JSON_EXISTS(a FORMAT JSON, '$')",
    "WITH RECURSIVE a(x) AS MATERIALIZED (SELECT 1 UNION ALL SELECT x FROM a) SEARCH DEPTH FIRST BY x SET o CYCLE x SET c TO true DEFAULT false USING p SELECT DISTINCT ON (x) x FROM a ORDER BY x USING < LIMIT 1 OFFSET 2",
    "SELECT 1 UNION SELECT 2 INTERSECT SELECT 3 EXCEPT ALL SELECT 4 ORDER BY 1 FETCH FIRST 2 ROWS WITH TIES",
    "VALUES (1, DEFAULT), (2, 3)",
    "TABLE t",
    "SELECT * FROM t FOR UPDATE OF t SKIP LOCKED",
    "SELECT 1 INTO TEMP x FROM t",
    "INSERT INTO s.t AS x (a, b[1], c.d) OVERRIDING SYSTEM VALUE SELECT 1 ON CONFLICT (a COLLATE \"C\" text_ops, (lower(b))) WHERE a DO UPDATE SET (a, b) = (SELECT 1, 2), c = EXCLUDED.c WHERE t.a RETURNING WITH (OLD AS o, NEW AS n) o.a, n.b, *",
    "INSERT INTO t DEFAULT VALUES",
    "INSERT INTO t VALUES (1) ON CONFLICT ON CONSTRAINT c DO NOTHING",
    "UPDATE t SET (a, b) = ROW(1, DEFAULT), c = DEFAULT FROM u WHERE CURRENT OF cur RETURNING *",
    "WITH w AS (DELETE FROM u USING v WHERE a RETURNING 1) UPDATE t SET a = 1",
    "WITH w AS (SELECT 1) DELETE FROM t",
    "DELETE FROM ONLY t USING u WHERE t.a = u.a RETURNING t.*",
    "MERGE INTO t USING u ON t.a = u.a WHEN MATCHED AND t.b THEN UPDATE SET c = 1 WHEN NOT MATCHED THEN INSERT (a) VALUES (1) WHEN NOT MATCHED BY SOURCE THEN DELETE",
    "WITH m AS (MERGE INTO t USING u ON true WHEN MATCHED THEN DO NOTHING RETURNING 1) SELECT 1",
    "SELECT",
];

/// How many messages of each type the walk visits.
fn walked(sql: &str) -> Result<BTreeMap<NodeType, usize>, Unreadable> {
    let tree = parse(sql)?;
    let mut seen = BTreeMap::new();
    for raw in tree.statements()? {
        for stmt in raw.nodes(number::RAWSTMT_STMT)? {
            walk(stmt, |message| {
                *seen.entry(message.of).or_default() += 1;
                Ok::<_, Unreadable>(())
            })?;
        }
    }
    Ok(seen)
}

/// The walk and the `pg_query` crate's own decoder see the same tree.
fn assert_same_tree(sql: &str) {
    let (want, named) = oracle::messages(sql).unwrap_or_else(|| panic!("decodes: {sql}"));
    let seen = walked(sql).unwrap_or_else(|err| panic!("{err:?}: {sql}"));
    assert_eq!(seen.values().sum::<usize>(), want, "{sql}");
    for (name, n) in named {
        let of = seen
            .iter()
            .find(|(of, _)| format!("{of:?}").to_lowercase() == name);
        // More where the type is also a typed field's.
        assert!(of.is_some_and(|(_, got)| *got >= n), "{name} x {n}: {sql}");
    }
}

#[test]
fn the_walk_sees_every_message() {
    for sql in COVER {
        assert_same_tree(sql);
    }
}

/// A type no statement here reaches is one whose fields nothing proves.
#[test]
fn every_node_type_is_covered() {
    let seen: BTreeSet<NodeType> = COVER
        .iter()
        .flat_map(|sql| walked(sql).expect("walks").into_keys())
        .collect();
    let unseen: Vec<NodeType> = (0..1000)
        .filter_map(schema::node)
        .filter(|of| !seen.contains(of))
        .collect();
    assert_eq!(unseen, vec![]);
}

/// A grammar of nested expressions and queries, for random trees.
fn arb_expr() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        Just("a".to_owned()),
        Just("t.b".to_owned()),
        Just("1".to_owned()),
        Just("'x'".to_owned()),
        Just("NULL".to_owned()),
        Just("$1".to_owned()),
        Just("current_date".to_owned()),
        Just("2.5".to_owned()),
    ];
    leaf.prop_recursive(6, 48, 3, |e| {
        prop_oneof![
            (e.clone(), e.clone()).prop_map(|(a, b)| format!("({a} + {b})")),
            (e.clone(), e.clone()).prop_map(|(a, b)| format!("({a} AND {b} OR NOT {a})")),
            (e.clone(), e.clone()).prop_map(|(a, b)| format!("f({a}, {b})")),
            e.clone().prop_map(|a| format!(
                "s.g(DISTINCT {a} ORDER BY {a}) FILTER (WHERE {a}) OVER (PARTITION BY {a})"
            )),
            (e.clone(), e.clone())
                .prop_map(|(a, b)| format!("CASE WHEN {a} THEN {b} ELSE {a} END")),
            e.clone().prop_map(|a| format!("({a})::int[]")),
            e.clone()
                .prop_map(|a| format!("(SELECT {a} FROM s.t JOIN u ON {a} WHERE {a})")),
            e.clone()
                .prop_map(|a| format!("EXISTS (SELECT FROM f({a}) x)")),
            (e.clone(), e.clone()).prop_map(|(a, b)| format!("({a} IN ({b}, 1))")),
            (e.clone(), e.clone())
                .prop_map(|(a, b)| format!("COALESCE({a}, EXTRACT(year FROM {b}))")),
            e.clone().prop_map(|a| format!("ARRAY[{a}, {a}]")),
            e.clone().prop_map(|a| format!("(ROW({a})).f[{a}]")),
            e.clone().prop_map(|a| format!("JSON_OBJECT('k': {a})")),
            e.clone().prop_map(|a| format!("(({a}) IS NOT NULL)")),
            e.prop_map(|a| format!("({a} BETWEEN SYMMETRIC {a} AND {a} COLLATE c)")),
        ]
    })
}

fn arb_statement() -> impl Strategy<Value = String> {
    (arb_expr(), 0..7u8).prop_map(|(e, shape)| match shape {
        0 => format!("SELECT {e}"),
        1 => format!("WITH w AS (SELECT {e}) SELECT * FROM w ORDER BY {e} LIMIT {e}"),
        2 => format!("SELECT {e} UNION ALL VALUES ({e}) EXCEPT SELECT {e}"),
        3 => format!(
            "INSERT INTO s.t SELECT {e} ON CONFLICT (a) DO UPDATE SET b = {e} RETURNING {e}"
        ),
        4 => format!("UPDATE t SET a = {e} FROM u WHERE {e}"),
        5 => format!("DELETE FROM t USING LATERAL (SELECT {e}) x WHERE {e}"),
        _ => format!("EXPLAIN SELECT 1 FROM t GROUP BY ROLLUP ({e}) HAVING {e}"),
    })
}

proptest! {
    #[test]
    fn random_statements_walk_as_they_decode(sql in arb_statement()) {
        assert_same_tree(&sql);
    }
}
