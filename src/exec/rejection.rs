//! A database's refusal of one statement, in a form safe to hand the agent.
//!
//! An agent can only fix a query it was told what is wrong with: 11 % of
//! measured `run_query` calls were syntax errors that all surfaced as one
//! opaque code. So a statement-level database error keeps its SQLSTATE and a
//! gateway-worded message keyed by it, naming at most the identifier at the
//! parser's error position in the caller's SQL (`pg/redact.rs`): the server's
//! text can carry row data.
//! Connect-phase errors never become a [`DbRejection`]: they can name the
//! role, host or authentication method.

use std::fmt;

/// Longest server message passed through; anything past it is cut. Primary
/// messages are one line, so this only bounds a pathological echo of input.
const MAX_MESSAGE_CHARS: usize = 512;

/// Stand-in for the configured role name inside a server message.
const ROLE_PLACEHOLDER: &str = "\"<role>\"";

/// What a rejection means to the caller. Tools map each to a stable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionKind {
    /// SQLSTATE `42501` (`insufficient_privilege`), or `25006`
    /// (`read_only_sql_transaction`): a write attempted inside the read
    /// tier's read-only transaction — e.g. by a function the guard cannot
    /// see into — is a missing write privilege, not a syntax error. Also a
    /// Redis `NOPERM` reply: the ACL user may not run that command or touch
    /// that key. Also Mongo's `Unauthorized` (code `13`).
    PermissionDenied,
    /// SQLSTATE `42P01` (`undefined_table`) or `42703` (`undefined_column`).
    UndefinedObject,
    /// Any other statement-level error.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbRejection {
    /// A Postgres SQLSTATE, a Redis error code, or a Mongo error code.
    sqlstate: String,
    message: String,
    position: Option<usize>,
    hint: Option<String>,
    near_misses: Vec<String>,
}

impl DbRejection {
    /// `role` is the configured target role; every quoted occurrence of it in
    /// `message` is replaced, because Postgres names the role in privilege
    /// errors (`permission denied to set role "app"`).
    pub(crate) fn new(sqlstate: &str, message: &str, role: &str) -> Self {
        Self {
            sqlstate: sqlstate.to_string(),
            message: redact_role(message, role),
            position: None,
            hint: None,
            near_misses: Vec::new(),
        }
    }

    /// `position` is a 1-based character offset into the caller's statement.
    pub(crate) fn with_position(mut self, position: Option<usize>) -> Self {
        self.position = position;
        self
    }

    /// `hint` is a server hint already judged free of row data (see
    /// `pg::redact::safe_hint`); the role is redacted here as in the message.
    pub(crate) fn with_hint(mut self, hint: Option<&str>, role: &str) -> Self {
        self.hint = hint.map(|hint| redact_role(hint, role));
        self
    }

    pub(crate) fn with_near_misses(mut self, near_misses: Vec<String>) -> Self {
        self.near_misses = near_misses;
        self
    }

    /// Move [`Self::position`] back by `chars`: the statement the target saw
    /// was the caller's behind a `chars`-long prefix (`EXPLAIN (…) `).
    pub(crate) fn behind_prefix(mut self, chars: usize) -> Self {
        self.position = self
            .position
            .and_then(|at| at.checked_sub(chars))
            .filter(|at| *at > 0);
        self
    }

    pub fn sqlstate(&self) -> &str {
        &self.sqlstate
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Where in the caller's statement the target located the error: a
    /// 1-based character offset, as Postgres reports it. `None` when the
    /// error was raised at run time or by another engine.
    pub fn position(&self) -> Option<usize> {
        self.position
    }

    /// The server's hint, only when it is a parser or catalog hint (SQLSTATE
    /// class `42`, raised at a position in the caller's statement), with the
    /// role redacted. Never `DETAIL`.
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// For an [`RejectionKind::UndefinedObject`]: up to five existing table
    /// or column names close to the one the caller typed, from the catalog
    /// the read role can see, closest first. Empty when none is close or the
    /// lookup did not finish in time.
    pub fn near_misses(&self) -> &[String] {
        &self.near_misses
    }

    pub fn kind(&self) -> RejectionKind {
        match self.sqlstate.as_str() {
            // Redis error codes are upper-case words, never five-character
            // SQLSTATEs, so the two code spaces cannot collide.
            // `13`: Mongo's `Unauthorized`. Numeric, so it collides with
            // neither five-character SQLSTATEs nor upper-case Redis codes.
            "42501" | "25006" | "NOPERM" | "13" => RejectionKind::PermissionDenied,
            "42P01" | "42703" => RejectionKind::UndefinedObject,
            _ => RejectionKind::Other,
        }
    }
}

/// `text` with every quoted occurrence of `role` replaced, cut to
/// [`MAX_MESSAGE_CHARS`].
fn redact_role(text: &str, role: &str) -> String {
    let quoted_role = format!("\"{role}\"");
    text.replace(&quoted_role, ROLE_PLACEHOLDER)
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

impl fmt::Display for DbRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.sqlstate, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_follows_sqlstate() {
        let kind = |code| DbRejection::new(code, "m", "app").kind();
        assert_eq!(kind("42501"), RejectionKind::PermissionDenied);
        assert_eq!(kind("25006"), RejectionKind::PermissionDenied);
        assert_eq!(kind("42P01"), RejectionKind::UndefinedObject);
        assert_eq!(kind("42703"), RejectionKind::UndefinedObject);
        assert_eq!(kind("42601"), RejectionKind::Other);
        assert_eq!(kind("NOPERM"), RejectionKind::PermissionDenied);
        assert_eq!(kind("WRONGTYPE"), RejectionKind::Other);
    }

    #[test]
    fn redacts_the_quoted_role_name_only() {
        let r = DbRejection::new(
            "42501",
            r#"permission denied to set role "app" for application"#,
            "app",
        );
        assert_eq!(
            r.message(),
            r#"permission denied to set role "<role>" for application"#
        );
        assert_eq!(r.to_string(), format!("42501 {}", r.message()));
    }

    #[test]
    fn hint_is_role_redacted_and_position_shifts_behind_a_prefix() {
        let r = DbRejection::new("42501", "m", "app")
            .with_position(Some(30))
            .with_hint(Some(r#"grant it to "app""#), "app")
            .behind_prefix(22);
        assert_eq!(r.hint(), Some(r#"grant it to "<role>""#));
        assert_eq!(r.position(), Some(8));
        assert_eq!(r.behind_prefix(9).position(), None);
    }

    #[test]
    fn caps_message_length() {
        let long = "x".repeat(MAX_MESSAGE_CHARS * 2);
        let r = DbRejection::new("22P02", &long, "app");
        assert_eq!(r.message().chars().count(), MAX_MESSAGE_CHARS);
    }
}
