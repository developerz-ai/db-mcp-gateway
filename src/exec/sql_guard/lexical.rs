//! Token-level refusals: text Postgres lexes differently from sqlparser, so
//! the AST the guard inspects would not be the statement the DB runs.

use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::tokenizer::{Location, Token, TokenWithSpan, Tokenizer};

use super::denylist::denied_relation;
use super::pg_scan::{self, Kind, Lexeme};
use super::{GuardError, SqlLocation};

const DIFFERENT_TOKENS: &str = "Postgres would split this text into different tokens; \
     spell literals, numbers and identifiers plainly";

/// Refuse text the two lexers do not read alike.
///
/// Unicode-escaped identifiers (`U&"\0070g_notify"`) come first, under
/// their own error: Postgres lexes `U&"…"` as one identifier and decodes its
/// escapes; sqlparser lexes it as `U`, `&`, `"…"` and keeps the escapes, so
/// `U&"\0070g_notify"(…)` calls `pg_notify` while the denylist sees
/// `\0070g_notify`. Refused rather than decoded: no agent needs the form,
/// and a refusal cannot decode wrongly.
///
/// Everything else is held against [`pg_scan::scan`]: both lexers must put
/// every word, quoted identifier, literal and parameter at the same bytes,
/// and agree on which bytes are comments. A disagreement means part of the
/// statement Postgres runs was a string or a comment to the guard.
///
/// Last, the names in the relation denylist, which are refused as words.
pub(super) fn check_lexical(sql: &str) -> Result<(), GuardError> {
    let tokens = Tokenizer::new(&PostgreSqlDialect {}, sql)
        .tokenize_with_location()
        .map_err(|err| GuardError::Parse(SqlLocation::of(err.location)))?;
    let escaped = tokens
        .windows(3)
        .any(|w| is_unicode_escaped_identifier(&w[0], &w[1], &w[2]));
    if escaped {
        return Err(GuardError::UnicodeEscapedIdentifier);
    }
    let postgres = pg_scan::scan(sql)?;
    if located(sql, &tokens).as_ref() != Some(&postgres) {
        return Err(GuardError::AmbiguousTokens(DIFFERENT_TOKENS));
    }
    match tokens.iter().find_map(denied_relation_name) {
        Some(denied) => Err(GuardError::DeniedRelation(denied)),
        None => Ok(()),
    }
}

/// A denied relation named anywhere in the text. Checked on tokens, not the
/// AST: sqlparser does not put every relation Postgres reads where a walk
/// finds it (`FROM ONLY t` parses as a table `ONLY` aliased `t`), and no
/// query needs one of these names as an alias.
fn denied_relation_name(token: &TokenWithSpan) -> Option<&'static str> {
    match &token.token {
        Token::Word(word) => denied_relation(&word.value),
        _ => None,
    }
}

/// sqlparser's tokens as byte-ranged lexemes, or `None` when its spans do
/// not walk the text front to back. Spans count lines and characters, so
/// the text is walked once alongside them.
fn located(sql: &str, tokens: &[TokenWithSpan]) -> Option<Vec<Lexeme>> {
    let mut out = Vec::new();
    let mut at = Location::new(1, 1);
    let mut start = 0;
    let mut chars = sql.char_indices();
    for token in tokens.iter().filter(|t| t.token != Token::EOF) {
        if token.span.start != at {
            return None;
        }
        let mut end = start;
        while at != token.span.end {
            let (i, c) = chars.next()?;
            end = i + c.len_utf8();
            at = match c {
                '\n' => Location::new(at.line + 1, 1),
                _ => Location::new(at.line, at.column + 1),
            };
        }
        if let Some(kind) = kind_of(&token.token, &sql[start..end]) {
            pg_scan::push(&mut out, kind, start, end);
        }
        start = end;
    }
    (start == sql.len()).then_some(out)
}

/// The coarse kind of a sqlparser token; `None` for whitespace and comments.
/// A literal form this list does not name counts as symbols, which the
/// Postgres scan never calls a literal — so it is refused.
fn kind_of(token: &Token, text: &str) -> Option<Kind> {
    Some(match token {
        Token::Whitespace(_) => return None,
        Token::Word(w) if w.quote_style.is_none() => Kind::Word,
        Token::Word(_) => Kind::QuotedIdent,
        Token::Number(..) => Kind::Number,
        Token::Placeholder(_) => Kind::Param,
        // `0x1F` and `X'1F'` share a token.
        Token::HexStringLiteral(_) if text.starts_with(|c: char| c.is_ascii_digit()) => {
            Kind::Number
        }
        Token::SingleQuotedString(_)
        | Token::EscapedStringLiteral(_)
        | Token::UnicodeStringLiteral(_)
        | Token::NationalStringLiteral(_)
        | Token::HexStringLiteral(_)
        | Token::SingleQuotedByteStringLiteral(_)
        | Token::DollarQuotedString(_) => Kind::Str,
        _ => Kind::Symbols,
    })
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
