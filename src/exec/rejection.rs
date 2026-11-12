//! A database's refusal of one statement, in a form safe to hand the agent.
//!
//! An agent can only fix a query it was told what is wrong with: 11 % of
//! measured `run_query` calls were syntax errors that all surfaced as one
//! opaque code (plan 101, 01 finding 6). So a statement-level database error
//! keeps its SQLSTATE and the server's primary message. Connect-phase errors
//! never become a [`DbRejection`] — they can name the role, host or
//! authentication method — and the message has the configured role name
//! redacted before it leaves the adapter.

use std::fmt;

/// Longest server message passed through; anything past it is cut. Primary
/// messages are one line, so this only bounds a pathological echo of input.
const MAX_MESSAGE_CHARS: usize = 512;

/// Stand-in for the configured role name inside a server message.
const ROLE_PLACEHOLDER: &str = "\"<role>\"";

/// What a rejection means to the caller. Tools map each to a stable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionKind {
    /// SQLSTATE `42501` (`insufficient_privilege`).
    PermissionDenied,
    /// SQLSTATE `42P01` (`undefined_table`) or `42703` (`undefined_column`).
    UndefinedObject,
    /// Any other statement-level error.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbRejection {
    sqlstate: String,
    message: String,
}

impl DbRejection {
    /// `role` is the configured target role; every quoted occurrence of it in
    /// `message` is replaced, because Postgres names the role in privilege
    /// errors (`permission denied to set role "app"`).
    pub(crate) fn new(sqlstate: &str, message: &str, role: &str) -> Self {
        let quoted_role = format!("\"{role}\"");
        let redacted = message.replace(&quoted_role, ROLE_PLACEHOLDER);
        Self {
            sqlstate: sqlstate.to_string(),
            message: redacted.chars().take(MAX_MESSAGE_CHARS).collect(),
        }
    }

    pub fn sqlstate(&self) -> &str {
        &self.sqlstate
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn kind(&self) -> RejectionKind {
        match self.sqlstate.as_str() {
            "42501" => RejectionKind::PermissionDenied,
            "42P01" | "42703" => RejectionKind::UndefinedObject,
            _ => RejectionKind::Other,
        }
    }
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
        assert_eq!(kind("42P01"), RejectionKind::UndefinedObject);
        assert_eq!(kind("42703"), RejectionKind::UndefinedObject);
        assert_eq!(kind("42601"), RejectionKind::Other);
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
    fn caps_message_length() {
        let long = "x".repeat(MAX_MESSAGE_CHARS * 2);
        let r = DbRejection::new("22P02", &long, "app");
        assert_eq!(r.message().chars().count(), MAX_MESSAGE_CHARS);
    }
}
