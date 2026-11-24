//! The one boolean env-flag parser (`TLS_DISABLED`, `ALLOW_INSECURE_SIGNING_KEY`).
//! Strict: a typo in a security switch must fail boot, not silently read as
//! `false` (or, worse, as `true`).

/// A boolean env var whose value is none of the accepted spellings.
#[derive(Debug, thiserror::Error)]
#[error("invalid {var} `{value}`: expected `true`/`false`, `1`/`0` or `yes`/`no`")]
pub struct BoolFlagError {
    pub var: &'static str,
    pub value: String,
}

/// Parse `raw` as `true`/`false`, `1`/`0` or `yes`/`no`, ASCII
/// case-insensitive, surrounding whitespace ignored; empty reads as `false`
/// (the spellings `TLS_DISABLED` accepted before this parser existed).
/// Anything else is an error.
pub fn parse_bool_flag(var: &'static str, raw: &str) -> Result<bool, BoolFlagError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" | "" => Ok(false),
        _ => Err(BoolFlagError {
            var,
            value: raw.to_string(),
        }),
    }
}

/// `var` from the process env: `Ok(None)` when unset, otherwise strictly parsed.
pub fn bool_flag_from_env(var: &'static str) -> Result<Option<bool>, BoolFlagError> {
    std::env::var(var)
        .ok()
        .map(|raw| parse_bool_flag(var, &raw))
        .transpose()
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
    fn rejects_everything_else_naming_the_var() {
        for raw in ["on", "off", "2", "truee", "t", "y"] {
            let err = parse_bool_flag("TLS_DISABLED", raw).unwrap_err();
            assert!(err.to_string().contains("TLS_DISABLED"), "{err}");
        }
    }
}
