//! The wire bytes themselves: what the schema does not describe is refused,
//! and no bytes panic, loop or use up a stack.

use proptest::prelude::*;

use super::pg_tree::COVER;
use crate::exec::sql_guard::pg_tree::schema::{self, NodeType, number};
use crate::exec::sql_guard::pg_tree::wire::{Field, Message, walk};
use crate::exec::sql_guard::pg_tree::{Unreadable, parse};

fn walk_bytes(of: NodeType, bytes: &[u8]) -> Result<usize, Unreadable> {
    let mut seen = 0;
    walk(Message::new(of, bytes), |_| {
        seen += 1;
        Ok::<_, Unreadable>(())
    })?;
    Ok(seen)
}

/// Bytes no statement's tree is, each refused for its own reason.
#[test]
fn bytes_the_schema_does_not_describe_are_refused() {
    let malformed = Err(Unreadable::Malformed);
    for (what, of, bytes, want) in [
        ("an empty message", NodeType::SelectStmt, &[][..], Ok(1)),
        ("a NULL node", NodeType::SelectStmt, &[0x1a, 0], Ok(1)),
        (
            "a field number past the last",
            NodeType::String,
            &[0x12, 0],
            malformed,
        ),
        ("field number 0", NodeType::String, &[0x02, 0], malformed),
        ("text as a varint", NodeType::String, &[0x08, 1], malformed),
        (
            "a node as a varint",
            NodeType::SelectStmt,
            &[0x18, 1],
            malformed,
        ),
        (
            "a fixed 64-bit value",
            NodeType::String,
            &[0x09, 0, 0, 0, 0, 0, 0, 0, 0],
            malformed,
        ),
        (
            "a fixed 32-bit value",
            NodeType::String,
            &[0x0d, 0, 0, 0, 0],
            malformed,
        ),
        (
            "a fixed 32-bit varint",
            NodeType::AConst,
            &[0x5d, 0, 0, 0, 0],
            malformed,
        ),
        (
            "a fixed 64-bit varint",
            NodeType::AConst,
            &[0x59, 0, 0, 0, 0, 0, 0, 0, 0],
            malformed,
        ),
        ("a group", NodeType::String, &[0x0b, 0x0c], malformed),
        (
            "a length past the end",
            NodeType::String,
            &[0x0a, 5, b'a'],
            malformed,
        ),
        ("a cut length", NodeType::String, &[0x0a, 0x80], malformed),
        (
            "an endless varint",
            NodeType::AConst,
            &[
                0x50, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
            ],
            malformed,
        ),
        (
            "a tag past 32 bits",
            NodeType::String,
            &[0xfa, 0xff, 0xff, 0xff, 0xff, 0x7f, 0],
            malformed,
        ),
        // Target list, holding node type 5: `Var`, which only analysis makes.
        (
            "a node type not listed",
            NodeType::SelectStmt,
            &[0x1a, 2, 0x2a, 0],
            Err(Unreadable::Node),
        ),
        (
            "a node of two types",
            NodeType::SelectStmt,
            &[0x1a, 4, 0x0a, 0, 0x12, 0],
            malformed,
        ),
        (
            "a node of a number",
            NodeType::SelectStmt,
            &[0x1a, 2, 0x08, 1],
            malformed,
        ),
        // `IntoClause.view_query`, which only analysis fills.
        (
            "a field analysis fills",
            NodeType::IntoClause,
            &[0x3a, 0],
            malformed,
        ),
    ] {
        assert_eq!(walk_bytes(of, bytes), want, "{what}");
    }
}

#[test]
fn reading_a_field_refuses_what_it_is_not() {
    let message = |bytes| Message::new(NodeType::FuncCall, bytes);
    let malformed = Unreadable::Malformed;
    assert_eq!(message(&[]).number(10), Ok(0));
    assert_eq!(message(&[0x50, 4]).number(10), Ok(4));
    assert_eq!(message(&[0x52, 0]).number(10), Err(malformed));
    assert_eq!(message(&[0x50, 4, 0x50, 4]).number(10), Err(malformed));
    assert_eq!(message(&[0x0a, 2, 0xc3, 0x28]).text(1), Err(malformed));
    assert_eq!(message(&[0x08, 1]).text(1), Err(malformed));
    assert_eq!(
        message(&[0x08, 1]).nodes(1).map(|n| n.len()),
        Err(malformed)
    );
    let typed = message(&[0x08, 1]).messages(1, NodeType::String);
    assert_eq!(typed.map(|m| m.len()), Err(malformed));
}

/// `SelectStmt.larg` in `SelectStmt.larg`, 100,000 deep, on 64 KiB of stack.
#[test]
fn depth_costs_no_stack() {
    let mut bytes = Vec::new();
    for _ in 0..100_000 {
        let mut len = bytes.len();
        let mut outer = vec![0x9a, 0x01];
        while len > 0x7f {
            outer.push((len & 0x7f) as u8 | 0x80);
            len >>= 7;
        }
        outer.push(len as u8);
        // Grows at the front: built back to front and reversed below.
        outer.reverse();
        bytes.extend(outer);
    }
    bytes.reverse();
    let seen = std::thread::Builder::new()
        .stack_size(64 << 10)
        .spawn(move || walk_bytes(NodeType::SelectStmt, &bytes))
        .expect("thread spawns")
        .join()
        .expect("the walk returns");
    assert_eq!(seen, Ok(100_001));
}

#[test]
fn schema_declares_text_where_names_are_read() {
    for (of, at) in [
        (NodeType::String, number::STRING_SVAL),
        (NodeType::RangeVar, number::RANGEVAR_CATALOGNAME),
        (NodeType::RangeVar, number::RANGEVAR_SCHEMANAME),
        (NodeType::RangeVar, number::RANGEVAR_RELNAME),
        (NodeType::DefElem, number::DEFELEM_DEFNAME),
    ] {
        assert_eq!(schema::fields(of)[at as usize - 1], Field::Text, "{of:?}");
    }
}

proptest! {
    /// A damaged tree ends in an answer, never a panic or a loop.
    #[test]
    fn damaged_bytes_get_an_answer(
        statement in 0..COVER.len(),
        damage in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
        cut in any::<prop::sample::Index>(),
    ) {
        let tree = parse(COVER[statement]).expect("parses");
        for raw in tree.statements().expect("one") {
            for stmt in raw.nodes(number::RAWSTMT_STMT).expect("a node") {
                let mut bytes = stmt.bytes().to_vec();
                if bytes.is_empty() {
                    continue;
                }
                for (at, byte) in &damage {
                    let at = at.index(bytes.len());
                    bytes[at] = *byte;
                }
                let _ = walk_bytes(stmt.of, &bytes);
                bytes.truncate(cut.index(bytes.len()));
                let _ = walk_bytes(stmt.of, &bytes);
            }
        }
    }

    #[test]
    fn any_bytes_get_an_answer(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
        let _ = walk_bytes(NodeType::SelectStmt, &bytes);
        let message = Message::new(NodeType::FuncCall, &bytes);
        let _ = (message.text(1), message.number(10), message.nodes(1).map(|n| n.len()));
    }
}
