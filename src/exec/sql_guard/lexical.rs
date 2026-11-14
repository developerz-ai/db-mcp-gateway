//! Token-level refusals: text Postgres lexes differently from sqlparser, so
//! the AST the guard inspects would not be the statement the DB runs.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::tokenizer::{Token, TokenWithSpan, Tokenizer};

use super::GuardError;

/// Refuse Unicode-escaped identifiers (`U&"\0070g_notify"`). Postgres lexes
/// `U&"…"` as one identifier and decodes its escapes; sqlparser lexes it as
/// `U`, `&`, `"…"` and keeps the escapes, so `U&"\0070g_notify"(…)` calls
/// `pg_notify` while the denylist sees `\0070g_notify`. Refused rather than
/// decoded: no agent needs the form, and a refusal cannot decode wrongly.
pub(super) fn check_lexical(sql: &str) -> Result<(), GuardError> {
    let tokens = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .map_err(|_| GuardError::Parse)?;
    let escaped = tokens
        .windows(3)
        .any(|w| is_unicode_escaped_identifier(&w[0], &w[1], &w[2]));
    if escaped {
        return Err(GuardError::NotAllowed("Unicode-escaped identifier"));
    }
    Ok(())
}

/// `U&"…"` with nothing between the three tokens — Postgres's form. With any
/// whitespace it is a bitwise AND on both sides.
fn is_unicode_escaped_identifier(
    u: &TokenWithSpan,
    amp: &TokenWithSpan,
    id: &TokenWithSpan,
) -> bool {
    let is_u = matches!(&u.token, Token::Word(w) if w.quote_style.is_none() && w.value.eq_ignore_ascii_case("u"));
    let is_quoted_ident = matches!(&id.token, Token::Word(w) if w.quote_style == Some('"'));
    is_u && amp.token == Token::Ampersand
        && is_quoted_ident
        && u.span.end == amp.span.start
        && amp.span.end == id.span.start
}
