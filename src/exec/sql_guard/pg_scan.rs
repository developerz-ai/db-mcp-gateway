//! Token boundaries as Postgres's own scanner (`scan.l`) draws them. The
//! guard inspects sqlparser's reading of the text, the DB runs Postgres's;
//! [`scan`] is the second opinion `lexical` holds sqlparser's tokens against.
//! Only boundaries and coarse kinds are produced — never values — so there
//! is nothing here to decode wrongly.

use super::GuardError;

pub(super) const COMMENT_IN_OPERATOR: &str =
    "a comment starts directly after an operator; put a space between them";
pub(super) const SPLIT_STRING: &str =
    "two string literals are separated only by a line break; join them with ||";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Word,
    QuotedIdent,
    Str,
    Number,
    Param,
    /// Operators and punctuation. Adjacent ones are merged: how a run of
    /// them splits decides which operator runs, never which function.
    Symbols,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Lexeme {
    pub(super) kind: Kind,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// Append a lexeme, merging it into a directly preceding `Symbols` run.
pub(super) fn push(out: &mut Vec<Lexeme>, kind: Kind, start: usize, end: usize) {
    if kind == Kind::Symbols
        && let Some(last) = out.last_mut()
        && last.kind == Kind::Symbols
        && last.end == start
    {
        last.end = end;
        return;
    }
    out.push(Lexeme { kind, start, end });
}

/// The non-whitespace, non-comment lexemes of `sql`, in order.
///
/// Refuses two shapes outright, because Postgres reads them in a way no
/// other lexer is likely to: a comment opening inside a run of operator
/// characters (`1 >--…` is `>` then a comment), and quote-delimited strings
/// separated only by whitespace with a line break (one literal, whose
/// continuation inherits the first part's escape rules).
pub(super) fn scan(sql: &str) -> Result<Vec<Lexeme>, GuardError> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    // Whether the last lexeme was a quote-delimited string, and whether a
    // line break has been crossed since it closed.
    let mut after_string = false;
    let mut line_break = false;
    while let Some(&c) = b.get(i) {
        let next = b.get(i + 1).copied();
        match c {
            b'\n' | b'\r' => {
                line_break = true;
                i += 1;
                continue;
            }
            b' ' | b'\t' | 0x0b | 0x0c => {
                i += 1;
                continue;
            }
            _ if opens_comment(b, i) => {
                i = comment_end(b, i)?;
                continue;
            }
            _ => {}
        }
        let start = i;
        let (kind, end, string) = match c {
            b'\'' => {
                if after_string && line_break {
                    return Err(GuardError::AmbiguousTokens(SPLIT_STRING));
                }
                (Kind::Str, quoted_end(b, i, b'\'', false)?, true)
            }
            b'"' => (Kind::QuotedIdent, quoted_end(b, i, b'"', false)?, false),
            b'$' if next.is_some_and(|n| n.is_ascii_digit()) => {
                (Kind::Param, i + 1 + digits(b, i + 1), false)
            }
            b'$' => match dollar_quoted_end(sql, i)? {
                Some(end) => (Kind::Str, end, false),
                None => (Kind::Symbols, i + 1, false),
            },
            b'e' | b'E' if next == Some(b'\'') => {
                (Kind::Str, quoted_end(b, i + 1, b'\'', true)?, true)
            }
            b'b' | b'B' | b'x' | b'X' | b'n' | b'N' if next == Some(b'\'') => {
                (Kind::Str, quoted_end(b, i + 1, b'\'', false)?, true)
            }
            b'u' | b'U' if next == Some(b'&') && b.get(i + 2) == Some(&b'\'') => {
                (Kind::Str, quoted_end(b, i + 2, b'\'', false)?, true)
            }
            b'u' | b'U' if next == Some(b'&') && b.get(i + 2) == Some(&b'"') => {
                (Kind::QuotedIdent, quoted_end(b, i + 2, b'"', false)?, false)
            }
            _ if is_ident_start(c) => {
                let len = b[i..].iter().take_while(|&&c| is_ident_part(c)).count();
                (Kind::Word, i + len, false)
            }
            _ if c.is_ascii_digit() || (c == b'.' && next.is_some_and(|n| n.is_ascii_digit())) => {
                (Kind::Number, number_end(b, i), false)
            }
            _ if is_operator_char(c) => (Kind::Symbols, operator_end(b, i)?, false),
            _ => (Kind::Symbols, i + 1, false),
        };
        push(&mut out, kind, start, end);
        after_string = string;
        line_break = false;
        i = end;
    }
    Ok(out)
}

fn opens_comment(b: &[u8], i: usize) -> bool {
    matches!(
        (b.get(i), b.get(i + 1)),
        (Some(b'-'), Some(b'-')) | (Some(b'/'), Some(b'*'))
    )
}

/// End of the comment opening at `i`: a `--` comment stops before its line
/// break (`\n` or `\r`), a `/* */` comment nests.
fn comment_end(b: &[u8], i: usize) -> Result<usize, GuardError> {
    if b[i] == b'-' {
        let len = b[i..]
            .iter()
            .take_while(|&&c| c != b'\n' && c != b'\r')
            .count();
        return Ok(i + len);
    }
    let mut depth = 0usize;
    let mut j = i;
    while j < b.len() {
        match (b[j], b.get(j + 1)) {
            (b'/', Some(b'*')) => {
                depth += 1;
                j += 2;
            }
            (b'*', Some(b'/')) => {
                depth -= 1;
                j += 2;
                if depth == 0 {
                    return Ok(j);
                }
            }
            _ => j += 1,
        }
    }
    Err(GuardError::Parse)
}

/// End of the quoted run whose opening quote is at `open`. A doubled quote
/// is the quote itself; a backslash escapes the next byte only in an
/// `E'…'` string.
fn quoted_end(b: &[u8], open: usize, quote: u8, backslash: bool) -> Result<usize, GuardError> {
    let mut j = open + 1;
    while let Some(&c) = b.get(j) {
        if c == b'\\' && backslash {
            j += 2;
        } else if c != quote {
            j += 1;
        } else if b.get(j + 1) == Some(&quote) {
            j += 2;
        } else {
            return Ok(j + 1);
        }
    }
    Err(GuardError::Parse)
}

/// End of the dollar-quoted string opening at `i` (`$$…$$`, `$tag$…$tag$`),
/// or `None` when the `$` opens no delimiter.
fn dollar_quoted_end(sql: &str, i: usize) -> Result<Option<usize>, GuardError> {
    let b = sql.as_bytes();
    let tag_len = match b.get(i + 1) {
        Some(&c) if is_ident_start(c) => b[i + 1..]
            .iter()
            .take_while(|&&c| is_ident_part(c) && c != b'$')
            .count(),
        _ => 0,
    };
    let body = i + 1 + tag_len + 1;
    if b.get(body - 1) != Some(&b'$') {
        return Ok(None);
    }
    let delimiter = &sql[i..body];
    match sql[body..].find(delimiter) {
        Some(at) => Ok(Some(body + at + delimiter.len())),
        None => Err(GuardError::Parse),
    }
}

/// End of the numeric literal at `i`: integer (also `0x…`), decimal, or
/// either with an exponent. `1..2` keeps its dots out of the number.
fn number_end(b: &[u8], i: usize) -> usize {
    if b[i] == b'0'
        && matches!(b.get(i + 1), Some(b'x' | b'X'))
        && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
    {
        let len = b[i + 2..]
            .iter()
            .take_while(|c| c.is_ascii_hexdigit() || **c == b'_')
            .count();
        return i + 2 + len;
    }
    let mut j = i + digits(b, i);
    if b.get(j) == Some(&b'.') && b.get(j + 1) != Some(&b'.') {
        j += 1;
        j += digits(b, j);
    }
    if matches!(b.get(j), Some(b'e' | b'E')) {
        let sign = usize::from(matches!(b.get(j + 1), Some(b'+' | b'-')));
        let exponent = digits(b, j + 1 + sign);
        if exponent > 0 {
            j += 1 + sign + exponent;
        }
    }
    j
}

/// Length of the run of digits (and `_` separators) at `i`; zero unless it
/// opens with a digit.
fn digits(b: &[u8], i: usize) -> usize {
    if !b.get(i).is_some_and(u8::is_ascii_digit) {
        return 0;
    }
    b[i..]
        .iter()
        .take_while(|c| c.is_ascii_digit() || **c == b'_')
        .count()
}

/// End of the operator at `i`. Postgres ends an operator where a comment
/// opens, so a comment opening inside the run is refused.
fn operator_end(b: &[u8], i: usize) -> Result<usize, GuardError> {
    let mut j = i + 1;
    while b.get(j).is_some_and(|&c| is_operator_char(c)) {
        if opens_comment(b, j) {
            return Err(GuardError::AmbiguousTokens(COMMENT_IN_OPERATOR));
        }
        j += 1;
    }
    Ok(j)
}

/// Every byte of a multi-byte character is an identifier character.
fn is_ident_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || !c.is_ascii()
}

fn is_ident_part(c: u8) -> bool {
    is_ident_start(c) || c.is_ascii_digit() || c == b'$'
}

fn is_operator_char(c: u8) -> bool {
    matches!(
        c,
        b'~' | b'!'
            | b'@'
            | b'#'
            | b'^'
            | b'&'
            | b'|'
            | b'`'
            | b'?'
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'<'
            | b'>'
            | b'='
    )
}
