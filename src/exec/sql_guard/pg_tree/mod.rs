//! Postgres's parse tree of a statement, read off the protobuf bytes
//! libpg_query serialises it to.
//!
//! The `pg_query` crate decodes those bytes into structs, recursing once per
//! node and giving up at 100 levels: 45 chained operators. [`wire::walk`]
//! keeps its own stack on the heap instead, so depth costs no call stack. It
//! is closed on every side: a node type, field or wire type [`schema`] does
//! not name refuses the statement.

mod ffi;
pub(super) mod schema;
pub(super) mod wire;

pub(super) use ffi::parse;

/// Why a tree could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unreadable {
    /// Postgres's grammar refuses the text.
    Syntax,
    /// Deeper than libpg_query parses or serialises.
    TooDeep,
    /// A node type no guarded statement holds: another kind of statement.
    Node,
    /// Not what the schema describes.
    Malformed,
}
