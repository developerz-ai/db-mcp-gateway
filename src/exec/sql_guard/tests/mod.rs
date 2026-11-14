use super::*;

mod denied_families;
mod denied_functions;
mod lexical;
mod read_only;
mod write_access;

fn ok(sql: &str) {
    assert!(
        is_read_only(sql).is_ok(),
        "expected `{sql}` to be allowed, got {:?}",
        is_read_only(sql)
    );
}

fn rejected(sql: &str, want: GuardError) {
    let got = is_read_only(sql);
    assert_eq!(
        got,
        Err(want.clone()),
        "expected `{sql}` rejected as {want:?}, got {got:?}"
    );
}

fn rejected_not_allowed(sql: &str, kind: &str) {
    match is_read_only(sql) {
        Err(GuardError::NotAllowed(got)) => assert_eq!(got, kind, "for `{sql}`"),
        other => panic!("expected NotAllowed({kind}) for `{sql}`, got {other:?}"),
    }
}
