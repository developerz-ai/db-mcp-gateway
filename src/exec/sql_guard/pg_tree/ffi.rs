//! The one `unsafe` module: libpg_query's parse call. The `pg_query` crate
//! links the library but keeps its bindings private and hands out no
//! undecoded tree, so the two symbols are declared here as the pinned
//! release's `pg_query.h` has them.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int};

// Links the static library that defines the symbols below.
use pg_query as _;

use super::Unreadable;
use super::schema::{NodeType, number};
use super::wire::Message;

/// The schema's Postgres major: node numbers move between majors.
const MAJOR: u64 = 18;

/// The largest tree a guarded statement yields is under 1 MiB.
const MAX_TREE_BYTES: usize = 16 << 20;

/// `PgQueryProtobuf`.
#[repr(C)]
#[derive(Debug)]
struct Protobuf {
    len: usize,
    data: *mut c_char,
}

/// `PgQueryError`, its other fields unread.
#[repr(C)]
#[derive(Debug)]
struct Error {
    message: *mut c_char,
    _funcname: *mut c_char,
    _filename: *mut c_char,
    _lineno: c_int,
    _cursorpos: c_int,
    _context: *mut c_char,
}

/// `PgQueryProtobufParseResult`.
#[repr(C)]
#[derive(Debug)]
struct ParseResult {
    parse_tree: Protobuf,
    _stderr_buffer: *mut c_char,
    error: *mut Error,
}

unsafe extern "C" {
    fn pg_query_parse_protobuf_opts(input: *const c_char, parser_options: c_int) -> ParseResult;
    fn pg_query_free_protobuf_parse_result(result: ParseResult);
}

/// A successful parse: a `ParseResult` message in C's memory.
#[derive(Debug)]
pub(in crate::exec::sql_guard) struct Tree(Parsed);

#[derive(Debug)]
struct Parsed(Option<ParseResult>);

impl Drop for Parsed {
    fn drop(&mut self) {
        if let Some(result) = self.0.take() {
            // SAFETY: the parse call returned `result`, and `take` leaves
            // nothing to free a second time.
            unsafe { pg_query_free_protobuf_parse_result(result) }
        }
    }
}

impl Parsed {
    /// Why C refused the text, when it did.
    fn refusal(&self) -> Option<Unreadable> {
        let error = self.0.as_ref()?.error;
        if error.is_null() {
            return None;
        }
        // SAFETY: a non-null error is a live `PgQueryError` until `drop`.
        let message = unsafe { (*error).message };
        if message.is_null() {
            return Some(Unreadable::Malformed);
        }
        // SAFETY: a non-null message is NUL-terminated and lives until `drop`.
        let message = unsafe { CStr::from_ptr(message) };
        Some(reason(message.to_bytes()))
    }

    fn bytes(&self) -> Option<&[u8]> {
        let tree = &self.0.as_ref()?.parse_tree;
        if tree.data.is_null() || tree.len > MAX_TREE_BYTES {
            return None;
        }
        // SAFETY: with no error set, `data` is `len` initialised bytes nothing
        // writes to until `drop`; `len` is under `isize::MAX`.
        Some(unsafe { std::slice::from_raw_parts(tree.data.cast::<u8>(), tree.len) })
    }
}

impl Tree {
    fn message(&self) -> Result<Message<'_>, Unreadable> {
        let bytes = self.0.bytes().ok_or(Unreadable::Malformed)?;
        Ok(Message::new(NodeType::ParseResult, bytes))
    }

    /// The statements, as `RawStmt`s.
    pub(in crate::exec::sql_guard) fn statements(&self) -> Result<Vec<Message<'_>>, Unreadable> {
        self.message()?
            .messages(number::PARSERESULT_STMTS, NodeType::RawStmt)
    }
}

/// The tree Postgres's grammar gives `sql`.
///
/// Call it on a [`super::super::parser_pool`] thread only: libpg_query sizes
/// its recursion limit from the bounds of the thread's own stack, so on a
/// small or grown stack the limit is wrong. The limit is 2 MiB.
pub(in crate::exec::sql_guard) fn parse(sql: &str) -> Result<Tree, Unreadable> {
    let input = CString::new(sql).map_err(|_| Unreadable::Syntax)?;
    // SAFETY: `input` is NUL-terminated and outlives the call, which keeps no
    // reference to it; the library's state is thread-local.
    let parsed = Parsed(Some(unsafe {
        pg_query_parse_protobuf_opts(input.as_ptr(), 0)
    }));
    if let Some(refusal) = parsed.refusal() {
        return Err(refusal);
    }
    let tree = Tree(parsed);
    check_version(tree.message()?)?;
    Ok(tree)
}

fn check_version(tree: Message<'_>) -> Result<(), Unreadable> {
    match tree.number(number::PARSERESULT_VERSION)? / 10_000 {
        MAJOR => Ok(()),
        _ => Err(Unreadable::Malformed),
    }
}

/// Depth refusals: `check_stack_depth`'s, the serialiser's and bison's.
fn reason(message: &[u8]) -> Unreadable {
    let too_deep = message == b"stack depth limit exceeded"
        || message == b"parse tree is nested too deeply to serialize to protobuf"
        || message.starts_with(b"memory exhausted at or near");
    if too_deep {
        Unreadable::TooDeep
    } else {
        Unreadable::Syntax
    }
}

#[cfg(test)]
mod tests;
