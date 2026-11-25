//! Bounds on the statement the parser is given, and the stack it runs on.
//!
//! sqlparser limits most of its own recursion, with two exceptions: it does
//! not count a join nested without a constraint, or a parenthesized list of
//! nested column definitions or options. Each level of the first consumes a
//! `JOIN`, each level of the second an opening parenthesis, so counting those
//! bounds them. It also builds a chain of operators in a loop, one tree level
//! per operator, and dropping the tree walks every level; [`MAX_SQL_BYTES`]
//! bounds that. [`with_parser_stack`] holds all of it at once.
//!
//! Counts only, never grammar: a count cannot be smaller than the structure
//! the parser builds from the words.

use super::GuardError;
use super::pg_scan::{Kind, Lexeme};

/// The tool edge already caps `sql` here; repeated because the stack below is
/// sized for it.
pub(super) const MAX_SQL_BYTES: usize = 64 * 1024;
/// Across the whole statement. The parser takes up to 8 KiB of stack per join.
pub(super) const MAX_JOINS: usize = 512;
/// Across the whole statement. Each takes about 14 KiB of heap.
pub(super) const MAX_SELECTS: usize = 1024;
/// Open at once.
pub(super) const MAX_PARENS: usize = 128;
/// The parser's own recursion limit: calls, subqueries, `CASE`, `NOT`, a
/// level or more each. Its default of 50 refuses ordinary generated `CASE`s.
pub(super) const MAX_NESTING: usize = 128;

/// Within the bounds the parser needs up to 6 MiB as measured, and under
/// 10 MiB were every limit reached at once. Mapped on demand: a call touches
/// only the pages it uses.
const PARSER_STACK: usize = 32 << 20;

/// Run `f` on a stack that holds parsing, walking and dropping any statement
/// within the bounds, whatever is left of the caller's.
pub(super) fn with_parser_stack<T>(f: impl FnOnce() -> T) -> T {
    stacker::grow(PARSER_STACK, f)
}

pub(super) fn check_length(sql: &str) -> Result<(), GuardError> {
    at_most(sql.len(), MAX_SQL_BYTES, "bytes")
}

pub(super) fn check_bounds(sql: &str, lexemes: &[Lexeme]) -> Result<(), GuardError> {
    let (mut joins, mut selects, mut open) = (0, 0, 0usize);
    for lexeme in lexemes {
        let text = &sql[lexeme.start..lexeme.end];
        match lexeme.kind {
            Kind::Word if text.eq_ignore_ascii_case("JOIN") => joins += 1,
            Kind::Word if text.eq_ignore_ascii_case("SELECT") => selects += 1,
            Kind::Symbols => {
                for symbol in text.bytes() {
                    match symbol {
                        b'(' => open += 1,
                        b')' => open = open.saturating_sub(1),
                        _ => {}
                    }
                    at_most(open, MAX_PARENS, "levels of parentheses")?;
                }
            }
            _ => {}
        }
    }
    at_most(joins, MAX_JOINS, "joins")?;
    at_most(selects, MAX_SELECTS, "SELECTs")
}

fn at_most(count: usize, limit: usize, what: &'static str) -> Result<(), GuardError> {
    if count > limit {
        return Err(GuardError::TooComplex { limit, what });
    }
    Ok(())
}
