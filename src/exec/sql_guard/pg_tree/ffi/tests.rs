use super::*;

/// A result as C would return it, freed by nothing: `Parsed` is forgotten.
fn with(result: ParseResult, check: impl FnOnce(&Parsed)) {
    let parsed = Parsed(Some(result));
    check(&parsed);
    std::mem::forget(parsed);
}

fn result(data: *mut c_char, len: usize) -> ParseResult {
    ParseResult {
        parse_tree: Protobuf { len, data },
        _stderr_buffer: std::ptr::null_mut(),
        error: std::ptr::null_mut(),
    }
}

#[test]
fn null_or_oversized_tree_is_malformed() {
    let mut byte: c_char = 8;
    for (data, len) in [
        (std::ptr::null_mut(), 0),
        (std::ptr::null_mut(), 64),
        (&raw mut byte, MAX_TREE_BYTES + 1),
        (&raw mut byte, usize::MAX),
    ] {
        with(result(data, len), |parsed| {
            assert!(parsed.bytes().is_none(), "{data:?} {len}");
        });
    }
}

#[test]
fn error_without_a_message_is_malformed() {
    let mut error = Error {
        message: std::ptr::null_mut(),
        _funcname: std::ptr::null_mut(),
        _filename: std::ptr::null_mut(),
        _lineno: 0,
        _cursorpos: 0,
        _context: std::ptr::null_mut(),
    };
    let mut failed = result(std::ptr::null_mut(), 0);
    failed.error = &raw mut error;
    with(failed, |parsed| {
        assert_eq!(parsed.refusal(), Some(Unreadable::Malformed));
    });
}

#[test]
fn refusals_are_told_apart() {
    for (message, want) in [
        ("stack depth limit exceeded", Unreadable::TooDeep),
        (
            "parse tree is nested too deeply to serialize to protobuf",
            Unreadable::TooDeep,
        ),
        ("memory exhausted at or near \")\"", Unreadable::TooDeep),
        (
            "syntax error at or near \"stack depth limit exceeded\"",
            Unreadable::Syntax,
        ),
    ] {
        assert_eq!(reason(message.as_bytes()), want, "{message}");
    }
}

#[test]
fn text_c_cannot_take_is_refused() {
    assert_eq!(
        parse("SELECT 1\0; DROP TABLE t").err(),
        Some(Unreadable::Syntax)
    );
}

#[test]
fn nothing_but_comments_is_no_statement() {
    let tree = parse("-- nothing").expect("parses");
    assert_eq!(tree.statements().map(|s| s.len()), Ok(0));
}

/// Field 1, varint: 180006, 170000, 190000, and no field at all.
#[test]
fn another_majors_tree_is_malformed() {
    for (bytes, want) in [
        (&[8, 0xa6, 0xfe, 0x0a][..], Ok(())),
        (&[8, 0x90, 0xb0, 0x0a], Err(Unreadable::Malformed)),
        (&[8, 0xb0, 0xcc, 0x0b], Err(Unreadable::Malformed)),
        (&[], Err(Unreadable::Malformed)),
    ] {
        let got = check_version(Message::new(NodeType::ParseResult, bytes));
        assert_eq!(got, want, "{bytes:?}");
    }
}
