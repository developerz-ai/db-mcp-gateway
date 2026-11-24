use super::*;

// --- Text Postgres splits into tokens differently from sqlparser ---

fn ambiguous(sql: &str) {
    for access in [Access::ReadOnly, Access::ReadWrite] {
        let got = check_sql(sql, access);
        assert!(
            matches!(got, Err(GuardError::AmbiguousTokens(_))),
            "expected `{sql}` refused as ambiguous, got {got:?}"
        );
    }
}

/// Postgres ends an operator where a comment opens: `1 >--…` is `1 >` and a
/// comment, so the next line is code. sqlparser reads one operator `>--`
/// and the rest as its string operand.
#[test]
fn comment_opening_inside_an_operator_rejected() {
    for sql in [
        "SELECT 1 >--'\n 2, pg_notify($$jobs$$,$$x$$)--'",
        "SELECT 1 <--'\n 2, pg_notify('a', 'b')--'",
        "SELECT 1 ~/*'*/ 2, pg_notify('a', 'b') --'",
        "SELECT a =-- c\n 1 FROM t",
        "SELECT 2 */* c */ 3",
        "UPDATE t SET a = 1 >--'\n 2, b = lo_creat(1)--'",
    ] {
        ambiguous(sql);
    }
    let msg = is_read_only("SELECT 1 >-- c\n 2")
        .expect_err("refused")
        .to_string();
    assert!(msg.contains("put a space"), "{msg}");
}

/// Postgres joins string literals separated only by whitespace with a line
/// break, and the continuation keeps the first part's escape rules: after
/// `E'a'`, `'\' , '` is one piece and what follows it is code.
#[test]
fn string_literals_split_by_a_line_break_rejected() {
    for sql in [
        "SELECT E'a'\n'\\' , ' , pg_notify($$j$$,$$x$$) -- '",
        "SELECT 'a'\n'b'",
        "SELECT 'a'\r'b'",
        "SELECT 'a' \t\r\n  'b'",
        "SELECT 'a' -- c\n 'b'",
        "SELECT U&'a'\n'b'",
        "SELECT B'1'\n'0'",
        "SELECT X'1'\n'f'",
        "SELECT N'a'\n'b'",
    ] {
        ambiguous(sql);
    }
    let msg = is_read_only("SELECT 'a'\n'b'")
        .expect_err("refused")
        .to_string();
    assert!(msg.contains("join them with ||"), "{msg}");
}

/// Shapes with no rule of their own: the two lexers put a literal, a word
/// or a parameter at different bytes.
#[test]
fn any_other_token_disagreement_rejected() {
    for sql in [
        // sqlparser lets a backslash escape the quote in a hex string.
        r"SELECT X'\'' , pg_notify('a', 'b') , X'\''",
        // sqlparser reads a string prefix; Postgres an alias and an identifier.
        r#"SELECT 1 b"x""#,
        // sqlparser reads a `$1$` dollar-quote tag; Postgres a parameter.
        "SELECT $1$ , pg_notify('a', 'b') , $1$",
        "SELECT 1L",
    ] {
        ambiguous(sql);
    }
}

#[test]
fn text_both_lexers_read_alike_still_allowed() {
    for sql in [
        "SELECT 1 > -- c\n 2",
        "SELECT 1 > /* c */ 2",
        "SELECT a-- c\n FROM t",
        "SELECT count(*)-- c\n FROM t",
        "SELECT a - -1, a+b, a<->b, -1, 1e5, 1.5e-3, .5, 0x1F, 1_000 FROM t",
        "SELECT d->>'k', d#>>'{a,b}', d @> '{}', d ?| array['a'], a || 'x' FROM t",
        "SELECT 'a' ||\n 'b',\n 'c'",
        "SELECT 'a', -- c\n 'b'",
        "SELECT E'it\\'s', e'\\\\', N'x', B'101', X'1F', U&'\\0041'",
        "SELECT $$ it's -- not a comment $$, $q$ $$ $q$, $1",
        r#"SELECT "a ""b"" -- c", t."Col" FROM t"#,
        "SELECT naïve, \"ключ\", 'значение' FROM tablé",
        "SELECT 1\r\nFROM t\r\nWHERE a = 'x'\r\n",
        "SELECT\t1 /* a /* nested */ b */ , 2 -- end",
        "SELECT 1::int, '2020-01-01'::date, interval '1 day', a[1:2] FROM t",
        "SELECT e.id, b.id, n.id, x.id, u.id FROM e, b, n, x, u WHERE e.a = 'v'",
    ] {
        ok(sql);
    }
}
