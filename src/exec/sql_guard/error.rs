//! Why the guard refused a statement.

use sqlparser::tokenizer::Location;

/// Where in the statement the parser gave up: 1-based line and column, as
/// sqlparser reports them. Coordinates only — the parser's message, which
/// quotes the statement, is never kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SqlLocation {
    pub line: u64,
    pub column: u64,
}

impl SqlLocation {
    /// From sqlparser's location; line `0` marks an empty span, no place.
    pub(super) fn of(location: Location) -> Option<Self> {
        (location.line > 0).then_some(Self {
            line: location.line,
            column: location.column,
        })
    }

    /// The ` at Line: L, Column: C` suffix sqlparser ends a message with.
    pub(super) fn from_message(message: &str) -> Option<Self> {
        let (_, at) = message.rsplit_once(" at Line: ")?;
        let (line, column) = at.split_once(", Column: ")?;
        Self::of(Location::new(line.parse().ok()?, column.parse().ok()?))
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error(
        "could not parse SQL{}",
        .0.map(|at| format!(" at line {}, column {}", at.line, at.column)).unwrap_or_default()
    )]
    Parse(Option<SqlLocation>),
    #[error("multiple statements are not allowed (got {0})")]
    MultiStatement(usize),
    #[error(
        "statement type `{0}` is not allowed; only SELECT, EXPLAIN and, with a write grant, INSERT/UPDATE/DELETE"
    )]
    NotAllowed(&'static str),
    #[error("SELECT ... FOR UPDATE/SHARE is not allowed (acquires write locks)")]
    Locking,
    #[error("write statement `{0}` is not allowed inside a read-only query")]
    WriteInReadPath(&'static str),
    #[error("SELECT ... INTO is not allowed (it materializes a table)")]
    SelectInto,
    #[error("EXPLAIN ANALYZE is not allowed (it executes the query)")]
    ExplainAnalyze,
    #[error("Unicode-escaped identifiers (U&\"…\") are not allowed; spell the identifier plainly")]
    UnicodeEscapedIdentifier,
    #[error("the SQL text is ambiguous: {0}")]
    AmbiguousTokens(&'static str),
    #[error("the statement has more than {limit} {what}; split it into smaller statements")]
    TooComplex { limit: usize, what: &'static str },
    /// The parser took more steps than a statement of this length is allowed.
    #[error(
        "the statement exceeds the parser work budget ({limit} steps at its length); \
         nest it less deeply or split it into smaller statements"
    )]
    TooMuchWork { limit: usize },
    #[error(
        "relation `{0}` is not allowed (it shows other sessions' statements); use the db_activity tool"
    )]
    DeniedRelation(&'static str),
    /// Stable error code: `GUARD_DENIED_FUNCTION`.
    #[error("function `{0}` is not allowed (high-privilege server-side function)")]
    DeniedFunction(&'static str),
}

impl GuardError {
    /// Where an unparseable statement stopped parsing, when the parser said.
    pub fn location(&self) -> Option<SqlLocation> {
        match self {
            Self::Parse(at) => *at,
            _ => None,
        }
    }
}
