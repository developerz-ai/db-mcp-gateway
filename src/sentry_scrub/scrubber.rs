//! The compiled credential-scrubbing patterns and the string/JSON passes
//! every event field goes through.

use regex::Regex;

/// Sentinel substituted for every detected secret.
const REDACTED: &str = "***REDACTED***";

/// Matches `scheme://user:password@` and keeps the scheme, drops the creds.
/// Covers postgres/postgresql/mysql/mongodb(+srv)/mariadb/redis — anything
/// with a `\w[\w.+-]*` scheme and a `userinfo` segment before the host.
const URL_CREDS_PATTERN: &str = r"(\w[\w.+-]*://)[^/\s:@]+:[^/\s@]+@";

/// Matches `key=value` / `key: value` for credential-bearing keys.
/// Case-insensitive. `\S+` is greedy on the value so a trailing URL or token
/// is consumed whole.
const SECRET_PATTERN: &str = r"(?i)(password|passwd|pwd|secret|token|dsn)\s*[:=]\s*\S+";

/// Explicit allowlist of env names whose **values** must never reach GlitchTip
/// (the file-header list). These keys carry hostnames or signing secrets that
/// the other two regexes miss: a userinfo-less `STATE_DB_URL=…` leaks the
/// internal hostname (URL regex only strips embedded `user:pass@`), and
/// `SESSION_SIGNING_KEY=…` matches neither `key`/`url` nor a secret keyword.
/// Match the key by name, redact the whole value. Leading `\b` is zero-width,
/// so the replacement (`$1=…`) preserves the preceding char and won't fire on
/// `MY_STATE_DB_URL` (`_`→`S` is not a word boundary).
const SENSITIVE_KEY_PATTERN: &str = r"(?i)\b(STATE_DB_URL|TARGET_DB_URL|PERMISSIONS_DB_DSN|OIDC_CLIENT_SECRET|SESSION_SIGNING_KEY)\s*[:=]\s*\S+";

/// The scrubber could not be built. One failure mode only: a pattern that does
/// not compile under this build's `regex` features. Names the constant so the
/// operator does not have to diff three regexes against a feature list.
#[derive(Debug, thiserror::Error)]
#[error(
    "credential-scrubbing pattern `{name}` failed to compile; this build's `regex` features do not cover it — see the `regex` dependency in Cargo.toml and `bin/check-scrub-features`"
)]
pub(crate) struct ScrubberError {
    name: &'static str,
    #[source]
    source: regex::Error,
}

/// The compiled patterns, owned by the `before_send` hook for the life of the
/// process. Construction is the only place compilation can fail, so every
/// method below is total — there is no "scrubber that might not work" state to
/// branch on at send time.
pub(super) struct Scrubber {
    url_creds: Regex,
    sensitive_key: Regex,
    secret: Regex,
}

impl Scrubber {
    /// Compile the three patterns. The literals are static, so the only way
    /// this fails is a build whose `regex` features do not cover what they use
    /// (`unicode-case` for `(?i)`, `unicode-perl` for `\w`/`\s`/`\b`) — a
    /// dependency defect, surfaced at boot by [`super::init`].
    pub(super) fn new() -> Result<Self, ScrubberError> {
        Ok(Self {
            url_creds: compile("URL_CREDS_PATTERN", URL_CREDS_PATTERN)?,
            sensitive_key: compile("SENSITIVE_KEY_PATTERN", SENSITIVE_KEY_PATTERN)?,
            secret: compile("SECRET_PATTERN", SECRET_PATTERN)?,
        })
    }

    /// Redact connection-string credentials and secret assignments in `s`.
    ///
    /// Applied in three passes: URL userinfo first (so `dsn: postgres://u:p@h`
    /// loses `u:p` even though `dsn:…` also matches a later pass), then the
    /// sensitive-key allowlist (whole-value redact for the named env keys),
    /// then `key=value` secrets by keyword. Each pass replaces only the secret
    /// *portion* — text that matches nothing comes back byte-identical.
    pub(super) fn scrub_str(&self, s: &str) -> String {
        let after_url = self.url_creds.replace_all(s, format!("$1{REDACTED}@"));
        let after_key = self
            .sensitive_key
            .replace_all(&after_url, format!("$1={REDACTED}"));
        self.secret
            .replace_all(&after_key, format!("$1={REDACTED}"))
            .into_owned()
    }

    /// Recursively redact every JSON string leaf.
    pub(super) fn scrub_json(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => *s = self.scrub_str(s),
            serde_json::Value::Array(items) => items.iter_mut().for_each(|v| self.scrub_json(v)),
            serde_json::Value::Object(map) => map.values_mut().for_each(|v| self.scrub_json(v)),
            _ => {}
        }
    }
}

/// Compile one named pattern, tagging a failure with the constant's name.
fn compile(name: &'static str, pattern: &str) -> Result<Regex, ScrubberError> {
    Regex::new(pattern).map_err(|source| ScrubberError { name, source })
}
