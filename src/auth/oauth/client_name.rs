//! The RFC 7591 `client_name` a client asserts at `/register`. Shown on the
//! consent page as secondary, explicitly unverified text: an attacker picks it
//! (e.g. "Claude"), so the redirect host stays the line the user is told to
//! trust.

/// Longest `client_name` accepted, in characters, after trimming.
pub const MAX_CLIENT_NAME_CHARS: usize = 100;

/// A self-asserted client name: trimmed, non-empty, at most
/// [`MAX_CLIENT_NAME_CHARS`] characters, with no control or bidi-formatting
/// characters. Never HTML-safe — escape it at render time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientName(String);

/// A `client_name` `/register` refuses (`invalid_client_metadata`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidClientName {
    #[error("client_name must be at most 100 characters")]
    TooLong,
    #[error("client_name must not contain control or bidi-formatting characters")]
    ForbiddenChar,
}

impl ClientName {
    /// `Ok(None)` for a blank name: RFC 7591 makes the field optional, and a
    /// whitespace-only name says nothing.
    pub fn parse(raw: &str) -> Result<Option<Self>, InvalidClientName> {
        let name = raw.trim();
        if name.is_empty() {
            return Ok(None);
        }
        if name.chars().count() > MAX_CLIENT_NAME_CHARS {
            return Err(InvalidClientName::TooLong);
        }
        if name.chars().any(is_forbidden) {
            return Err(InvalidClientName::ForbiddenChar);
        }
        Ok(Some(Self(name.to_owned())))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Control characters would mangle the page and log lines; bidi overrides and
/// isolates would let a name visually reorder the text around it on the
/// consent page (e.g. pose as the redirect host).
fn is_forbidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_is_absent_and_names_are_trimmed() {
        assert_eq!(ClientName::parse(""), Ok(None));
        assert_eq!(ClientName::parse("   "), Ok(None));
        let name = ClientName::parse("  Claude Code ").unwrap().unwrap();
        assert_eq!(name.as_str(), "Claude Code");
    }

    #[test]
    fn length_is_bounded_in_characters_after_trim() {
        let max = "é".repeat(MAX_CLIENT_NAME_CHARS);
        assert!(ClientName::parse(&format!("  {max}  ")).unwrap().is_some());
        let over = "a".repeat(MAX_CLIENT_NAME_CHARS + 1);
        assert_eq!(ClientName::parse(&over), Err(InvalidClientName::TooLong));
    }

    #[test]
    fn control_and_bidi_characters_are_refused() {
        for bad in ["a\nb", "a\u{0}b", "a\u{7f}b", "a\u{202E}b", "a\u{2066}b"] {
            assert_eq!(
                ClientName::parse(bad),
                Err(InvalidClientName::ForbiddenChar),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn markup_is_accepted_verbatim_for_escaping_at_render() {
        let name = ClientName::parse("<script>alert(1)</script>").unwrap();
        assert_eq!(name.unwrap().as_str(), "<script>alert(1)</script>");
    }
}
