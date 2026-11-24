//! Validated SQL identifier — the only form in which a caller-supplied
//! schema or table name may reach generated SQL.
//!
//! Bind parameters can't carry identifiers (only values), so generated SQL
//! has to interpolate them. Validate-then-quote: an [`Identifier`] matches
//! exactly `^[A-Za-z_][A-Za-z0-9_]*$`, so wrapping it in `"..."` can never
//! close the quote or smuggle in a second token. Anything else (spaces,
//! quotes, semicolons, dashes, even valid-but-quoted-in-Postgres names like
//! `My Table`) is rejected — safer than trying to escape arbitrary input.
//! A Mongo collection name ([`Identifier::parse_collection`]) may also hold
//! `-` and `.`, which cannot close a double quote either.

/// The identifier rule, for callers that surface it in an error message.
pub const IDENTIFIER_PATTERN: &str = "^[A-Za-z_][A-Za-z0-9_]*$";

/// The Mongo collection-name rule: [`IDENTIFIER_PATTERN`] plus `-` and `.`
/// after the first character, never a trailing `.`.
pub const COLLECTION_PATTERN: &str = "^[A-Za-z_][A-Za-z0-9_.-]*$ (no trailing `.`)";

/// A schema or table name that passed [`Identifier::parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identifier<'a>(&'a str);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("identifier must match {IDENTIFIER_PATTERN}")]
pub struct InvalidIdentifier;

impl<'a> Identifier<'a> {
    pub fn parse(s: &'a str) -> Result<Self, InvalidIdentifier> {
        Self::parse_with(s, |c| c == '_')
    }

    /// A Mongo collection name: [`COLLECTION_PATTERN`]. Collections are
    /// routinely named `order-items` or `events.2024`. Still safe as a
    /// double-quoted SQL identifier: neither `-` nor `.` closes the quote.
    pub fn parse_collection(s: &'a str) -> Result<Self, InvalidIdentifier> {
        if s.ends_with('.') {
            return Err(InvalidIdentifier);
        }
        Self::parse_with(s, |c| matches!(c, '_' | '-' | '.'))
    }

    /// First character a letter or `_`; every other one alphanumeric or
    /// `extra`.
    fn parse_with(s: &'a str, extra: fn(char) -> bool) -> Result<Self, InvalidIdentifier> {
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return Err(InvalidIdentifier);
        };
        let valid = (first.is_ascii_alphabetic() || first == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || extra(c));
        if valid {
            Ok(Self(s))
        } else {
            Err(InvalidIdentifier)
        }
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for ok in [
            "users",
            "_private",
            "public",
            "USERS",
            "user_accounts",
            "t1",
            "_t_2",
            "X",
        ] {
            assert_eq!(Identifier::parse(ok).map(|i| i.as_str()), Ok(ok));
        }
    }

    #[test]
    fn rejects_anything_else() {
        for bad in [
            "",                        // empty
            "1users",                  // starts with digit
            "user accounts",           // space
            "users; DROP TABLE x; --", // injection attempt
            "\"users\"",               // pre-quoted
            "user-accounts",           // hyphen
            "users.private",           // dot
            "用户",                    // non-ASCII
            "users\nDROP",             // newline
            "users'",                  // quote
        ] {
            assert_eq!(
                Identifier::parse(bad),
                Err(InvalidIdentifier),
                "should reject `{bad}`"
            );
        }
    }

    #[test]
    fn collection_names_also_take_dashes_and_dots() {
        for ok in ["order-items", "events.2024", "a.b-c_d", "users"] {
            assert_eq!(Identifier::parse_collection(ok).map(|i| i.as_str()), Ok(ok));
        }
        for bad in [
            "", "-x", ".x", "x.", "a b", "a\"b", "a$b", "a;b", "用户", "a\0b",
        ] {
            assert_eq!(
                Identifier::parse_collection(bad),
                Err(InvalidIdentifier),
                "should reject `{bad}`"
            );
        }
    }

    #[test]
    fn error_message_names_the_pattern() {
        assert!(InvalidIdentifier.to_string().contains(IDENTIFIER_PATTERN));
    }
}
