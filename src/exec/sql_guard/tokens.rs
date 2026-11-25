//! Rules read off the lexemes alone. The tree may hold less than the text, or
//! read a word another way; these hold for the text whatever the tree says.
//! They repeat the visitor's answer for text the two read alike.

use super::GuardError;
use super::denylist::denied_function;
use super::pg_scan::{Kind, Lexeme};

/// Words that put a name before a parenthesis without calling it: a table and
/// its columns, an alias and its columns, a CTE and its columns.
const NAMING: &[&str] = &["INTO", "AS", "WITH", "RECURSIVE"];

pub(super) fn check_tokens(sql: &str, lexemes: &[Lexeme]) -> Result<(), GuardError> {
    let tokens: Vec<Token<'_>> = lexemes.iter().map(|l| Token::of(sql, l)).collect();
    for at in 0..tokens.len() {
        check_call(&tokens, at)?;
        check_clause(&tokens, at)?;
    }
    Ok(())
}

/// A lexeme with what the rules compare: its text, unquoted.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token<'a> {
    Word(&'a str),
    Quoted(String),
    Symbols(&'a str),
    /// A literal or a parameter.
    Value,
}

impl<'a> Token<'a> {
    fn of(sql: &'a str, lexeme: &Lexeme) -> Self {
        let text = &sql[lexeme.start..lexeme.end];
        match lexeme.kind {
            Kind::Word => Self::Word(text),
            Kind::QuotedIdent => Self::Quoted(unquoted(text)),
            Kind::Symbols => Self::Symbols(text),
            Kind::Str | Kind::Number | Kind::Param => Self::Value,
        }
    }

    fn name(&self) -> Option<&str> {
        match self {
            Self::Word(name) => Some(name),
            Self::Quoted(name) => Some(name),
            Self::Symbols(_) | Self::Value => None,
        }
    }

    fn is(&self, keyword: &str) -> bool {
        matches!(self, Self::Word(word) if word.eq_ignore_ascii_case(keyword))
    }
}

/// What a quoted identifier names.
fn unquoted(text: &str) -> String {
    let inner = text.strip_prefix('"').and_then(|t| t.strip_suffix('"'));
    inner.unwrap_or(text).replace("\"\"", "\"")
}

/// The word `at` is one of `keywords`. Out of range is none.
fn is_any(tokens: &[Token<'_>], at: Option<usize>, keywords: &[&str]) -> bool {
    at.and_then(|at| tokens.get(at))
        .is_some_and(|token| keywords.iter().any(|keyword| token.is(keyword)))
}

/// A denied name before an opening parenthesis is a call, unless the word
/// before the (qualified) name says it names something else.
fn check_call(tokens: &[Token<'_>], at: usize) -> Result<(), GuardError> {
    let Some(denied) = tokens[at].name().and_then(denied_function) else {
        return Ok(());
    };
    let called = matches!(tokens.get(at + 1), Some(Token::Symbols(s)) if s.starts_with('('));
    if !called || is_any(tokens, before_qualified(tokens, at), NAMING) {
        return Ok(());
    }
    Err(GuardError::DeniedFunction(denied))
}

/// The token before `a.b.name`, for the `name` at `at`.
fn before_qualified(tokens: &[Token<'_>], mut at: usize) -> Option<usize> {
    while at >= 2 && tokens[at - 1] == Token::Symbols(".") && tokens[at - 2].name().is_some() {
        at -= 2;
    }
    at.checked_sub(1)
}

/// A locking clause, or an `INTO` that is neither `INSERT INTO` nor a label.
fn check_clause(tokens: &[Token<'_>], at: usize) -> Result<(), GuardError> {
    let next = |n: usize, keywords: &[&str]| is_any(tokens, Some(at + n), keywords);
    let locks = next(1, &["UPDATE", "SHARE"])
        || (next(1, &["NO"]) && next(2, &["KEY"]))
        || (next(1, &["KEY"]) && next(2, &["SHARE"]));
    if tokens[at].is("FOR") && locks {
        return Err(GuardError::Locking);
    }
    let before = at.checked_sub(1);
    let label = is_any(tokens, before, &["AS", "INSERT"])
        || matches!(before.map(|b| &tokens[b]), Some(Token::Symbols(s)) if s.ends_with('.'));
    if tokens[at].is("INTO") && !label {
        return Err(GuardError::SelectInto);
    }
    Ok(())
}
