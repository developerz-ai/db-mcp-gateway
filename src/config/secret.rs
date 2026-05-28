//! Secret references in YAML config.
//!
//! Deliberately `Deserialize`-only: a `Password` MUST NOT round-trip back out
//! to a client response. Serializing it would defeat the whole point of having
//! credentials in this binary. Anything that goes over the wire uses
//! credential-free view types (see e.g. `tools::list_servers::SafeServerView`).
//!
//! Resolution of `vault:` / `aws-sm:` / `gcp-sm:` references against real
//! backends lands with issue #5 — for #3 we parse and store the reference but
//! never read its plaintext.

use serde::Deserialize;

/// A secret reference as written in YAML. The variant tells us where the real
/// value lives; we resolve lazily (and never log either the reference or the
/// resolved value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Password {
    /// Literal value inline in the YAML. Rejected in `env: production` by
    /// `Config::validate` (lands with issue #16's full validator).
    Literal(String),
    /// `${VAR_NAME}` — resolve from process env at startup.
    EnvVar(String),
    /// `vault:secret/path`, `aws-sm:arn:...`, `gcp-sm:projects/...` — resolved
    /// via the named backend.
    SecretBackend { scheme: String, reference: String },
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Password::from_raw(&raw))
    }
}

impl Password {
    pub fn from_raw(s: &str) -> Self {
        if let Some(rest) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
            return Password::EnvVar(rest.to_string());
        }
        if let Some((scheme, reference)) = s.split_once(':') {
            // Only treat as a backend reference when the scheme is recognised.
            // A bare colon in a literal password (e.g. "abc:123") stays literal.
            match scheme {
                "vault" | "aws-sm" | "gcp-sm" => {
                    return Password::SecretBackend {
                        scheme: scheme.to_string(),
                        reference: reference.to_string(),
                    };
                }
                _ => {}
            }
        }
        Password::Literal(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_each_form() {
        assert_eq!(
            Password::from_raw("${STATE_DB_PW}"),
            Password::EnvVar("STATE_DB_PW".into())
        );
        assert_eq!(
            Password::from_raw("vault:secret/prod/app_ro"),
            Password::SecretBackend {
                scheme: "vault".into(),
                reference: "secret/prod/app_ro".into()
            }
        );
        assert_eq!(
            Password::from_raw("aws-sm:arn:aws:secretsmanager:..."),
            Password::SecretBackend {
                scheme: "aws-sm".into(),
                reference: "arn:aws:secretsmanager:...".into()
            }
        );
        assert_eq!(
            Password::from_raw("hunter2"),
            Password::Literal("hunter2".into())
        );
        // A bare colon in an unknown-scheme value stays literal.
        assert_eq!(
            Password::from_raw("not-a-scheme:hunter2"),
            Password::Literal("not-a-scheme:hunter2".into())
        );
    }
}
