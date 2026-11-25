//! The guard's own parse of a statement, within the work budget.

use sqlparser::ast::Statement;
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::{Parser, ParserError};
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer};

use super::budget::{self, Work};
use super::{GuardError, SqlLocation};

/// The statements of `sql`, read to its end.
pub(super) fn parse(sql: &str) -> Result<Vec<Statement>, GuardError> {
    let (parsed, Work { steps, allowance }) = measured(sql)?;
    tracing::debug!(steps, allowance, "SQL guard parse");
    parsed
}

/// [`parse`], and the work it took; an error when `sql` has no tokens to parse.
pub(super) fn measured(
    sql: &str,
) -> Result<(Result<Vec<Statement>, GuardError>, Work), GuardError> {
    let tokens = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .map_err(|err| refusal(err.into()))?;
    let tokens = spaced_once(tokens);
    let count = tokens.iter().filter(|token| !is_space(token)).count();
    let allowance = budget::allowance(count, sql.len());
    Ok(budget::metered(allowance, |dialect| {
        let mut parser = Parser::new(dialect).with_tokens_with_locations(tokens);
        let statements = parser.parse_statements().map_err(refusal)?;
        let next = parser.peek_token_ref();
        match next.token {
            Token::EOF => Ok(statements),
            _ => Err(GuardError::Parse(SqlLocation::of(next.span.start))),
        }
    }))
}

fn refusal(err: ParserError) -> GuardError {
    match err {
        ParserError::ParserError(message) | ParserError::TokenizerError(message) => {
            GuardError::Parse(SqlLocation::from_message(&message))
        }
        ParserError::RecursionLimitExceeded => GuardError::Parse(None),
    }
}

/// `tokens`, one whitespace or comment where there were several: the parser
/// steps over each every time it looks ahead.
fn spaced_once(mut tokens: Vec<TokenWithSpan>) -> Vec<TokenWithSpan> {
    tokens.dedup_by(|next, kept| is_space(next) && is_space(kept));
    tokens
}

fn is_space(token: &TokenWithSpan) -> bool {
    matches!(token.token, Token::Whitespace(_))
}
