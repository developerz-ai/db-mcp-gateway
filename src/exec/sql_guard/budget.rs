//! The parser's work budget.
//!
//! sqlparser tries one reading of a text and, when that fails, another. It
//! remembers the readings that failed, but not every one that succeeded and
//! was dropped, so nesting can multiply the attempts and its own depth limit
//! does not bound them. The parser asks its dialect something on every way
//! down, so [`Metered`] counts the questions and ends a parse that asks more
//! than [`allowance`], which grows with the text alone.
//!
//! Ended by unwinding, not by an error: the parser answers an error with its
//! next reading, which could then be the one that stands.

use std::cell::Cell;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use sqlparser::dialect::{Dialect, PostgreSqlDialect};
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Token;

use super::GuardError;

/// Whatever the length. Statements of a few words use a few hundred.
const BASE_STEPS: usize = 25_000;
/// What copying a token costs.
const BYTES_PER_STEP: usize = 16;
/// For each token, comments and whitespace left out. The most seen in a
/// statement Postgres accepts is 8; nesting that retries needs far more.
const STEPS_PER_TOKEN: usize = 24;

/// Steps for a statement of `tokens` tokens in `bytes` bytes.
pub(super) fn allowance(tokens: usize, bytes: usize) -> usize {
    BASE_STEPS
        .saturating_add(STEPS_PER_TOKEN.saturating_mul(tokens))
        .saturating_add(bytes)
}

/// What a parse past its allowance unwinds with.
#[derive(Debug)]
struct Spent;

/// [`PostgreSqlDialect`], counting (`metered` has its methods).
#[derive(Debug)]
pub(super) struct Metered {
    pub(super) postgres: PostgreSqlDialect,
    allowance: usize,
    steps: Cell<usize>,
}

impl Metered {
    pub(super) fn step(&self) {
        self.spend(1);
    }

    /// A step at `parser`'s place in the text. The parser copies a token to
    /// look at it, so a long one costs more.
    pub(super) fn step_at(&self, parser: &Parser) {
        let token = &parser.peek_token_ref().token;
        self.spend(1 + text_len(token) / BYTES_PER_STEP);
    }

    fn spend(&self, spent: usize) {
        let steps = self.steps.get().saturating_add(spent);
        self.steps.set(steps);
        if steps > self.allowance {
            // Not a panic: the hook does not run, and `metered` catches it.
            resume_unwind(Box::new(Spent));
        }
    }
}

/// What a parse took, of what it was allowed.
#[derive(Debug, Clone, Copy)]
pub(super) struct Work {
    pub(super) steps: usize,
    pub(super) allowance: usize,
}

/// Run `parse` with a dialect that ends it past `allowance` steps. `parse`
/// keeps nothing it has not finished.
pub(super) fn metered<T>(
    allowance: usize,
    parse: impl FnOnce(&dyn Dialect) -> Result<T, GuardError>,
) -> (Result<T, GuardError>, Work) {
    let dialect = Metered {
        postgres: PostgreSqlDialect {},
        allowance,
        steps: Cell::new(0),
    };
    let parsed = match catch_unwind(AssertUnwindSafe(|| parse(&dialect))) {
        Ok(parsed) => parsed,
        Err(payload) if payload.is::<Spent>() => Err(GuardError::TooMuchWork { limit: allowance }),
        Err(payload) => resume_unwind(payload),
    };
    let steps = dialect.steps.get();
    (parsed, Work { steps, allowance })
}

/// Of the kinds whose length the statement chooses.
fn text_len(token: &Token) -> usize {
    match token {
        Token::Word(word) => word.value.len(),
        Token::Number(text, _)
        | Token::SingleQuotedString(text)
        | Token::EscapedStringLiteral(text)
        | Token::UnicodeStringLiteral(text)
        | Token::NationalStringLiteral(text)
        | Token::HexStringLiteral(text)
        | Token::SingleQuotedByteStringLiteral(text)
        | Token::CustomBinaryOperator(text)
        | Token::Placeholder(text) => text.len(),
        Token::DollarQuotedString(quoted) => quoted.value.len(),
        _ => 0,
    }
}
