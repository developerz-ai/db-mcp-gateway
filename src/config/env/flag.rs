//! The one boolean env-flag parser (`TLS_DISABLED`, `ALLOW_INSECURE_SIGNING_KEY`).
//! Strict: a typo in a security switch must fail boot, not silently read as
//! `false` (or, worse, as `true`).

use std::env::VarError;

/// A boolean env var whose value is none of the accepted spellings. Names the
/// variable only: a mis-mapped secret must not reach the boot log.
#[derive(Debug, thiserror::Error)]
#[error("invalid {var}: expected `true`/`false`, `1`/`0` or `yes`/`no`")]
pub struct BoolFlagError {
    pub var: &'static str,
}

/// Parse `raw` as `true`/`false`, `1`/`0` or `yes`/`no`, ASCII
/// case-insensitive, surrounding whitespace ignored; empty reads as `false`
/// (the spellings `TLS_DISABLED` accepted before this parser existed).
/// Anything else is an error.
pub fn parse_bool_flag(var: &'static str, raw: &str) -> Result<bool, BoolFlagError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" | "" => Ok(false),
        _ => Err(BoolFlagError { var }),
    }
}

/// `var` from the process env: `Ok(None)` when unset, otherwise strictly parsed.
pub fn bool_flag_from_env(var: &'static str) -> Result<Option<bool>, BoolFlagError> {
    flag_from_var(var, std::env::var(var))
}

/// A non-Unicode value is refused, not read as unset: unset means "default",
/// and a security switch must not fall back to it on a value it cannot read.
fn flag_from_var(
    var: &'static str,
    raw: Result<String, VarError>,
) -> Result<Option<bool>, BoolFlagError> {
    match raw {
        Ok(raw) => parse_bool_flag(var, &raw).map(Some),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(BoolFlagError { var }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_documented_spellings() {
        for (raw, want) in [
            ("true", true),
            ("TRUE", true),
            (" True ", true),
            ("1", true),
            ("false", false),
            ("FALSE", false),
            ("0", false),
            ("yes", true),
            ("No", false),
            ("", false),
        ] {
            assert_eq!(parse_bool_flag("X", raw).ok(), Some(want), "{raw}");
        }
    }

    #[test]
    fn a_rejected_value_never_reaches_the_error() {
        let material = "-----BEGIN PRIVATE KEY-----MIIEvQ";
        let err = parse_bool_flag("ALLOW_INSECURE_SIGNING_KEY", material).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(shown.contains("ALLOW_INSECURE_SIGNING_KEY"), "{shown}");
        assert!(!shown.contains("MIIEvQ"), "{shown}");
    }

    #[test]
    fn a_non_unicode_value_is_an_error_not_unset() {
        let raw = Err(std::env::VarError::NotUnicode("\u{FFFD}".into()));
        assert!(flag_from_var("TLS_DISABLED", raw).is_err());
        let unset = Err(std::env::VarError::NotPresent);
        assert_eq!(flag_from_var("TLS_DISABLED", unset).ok(), Some(None));
    }

    #[test]
    fn rejects_everything_else_naming_the_var() {
        for raw in ["on", "off", "2", "truee", "t", "y"] {
            let err = parse_bool_flag("TLS_DISABLED", raw).unwrap_err();
            assert!(err.to_string().contains("TLS_DISABLED"), "{err}");
        }
    }
}
