//! The compiled credential-scrubbing patterns and the string/JSON passes
//! every event field goes through.

use regex::Regex;
use serde_json::{Map, Value};

/// Sentinel substituted for every detected secret.
pub(super) const REDACTED: &str = "***REDACTED***";

/// Bare service bearer tokens (spec 14). Matched on their prefix alone so a
/// truncated token is redacted too.
const SERVICE_TOKEN_PATTERN: &str = r"dbmcp_svc_[0-9A-Za-z]+";

/// Compact JWS/JWT: base64url `{"…` header, payload, optional signature.
const JWT_PATTERN: &str = r"eyJ[\w-]{4,}\.[\w-]{4,}\.[\w-]*";

/// `Bearer <credential>` with or without an `Authorization:` key before it.
const BEARER_PATTERN: &str = r"(?i)\b(bearer\s+)[\w.~+/=-]+";

/// `scheme://userinfo@` — keeps the scheme, drops the userinfo. Two shapes:
/// `user:password@` / `:password@`, where the password may itself contain `/`
/// or `@` (the **last** `@` before whitespace, `?` or `#` delimits the host),
/// and a username-only `token@`.
const URL_CREDS_PATTERN: &str = r"(\w[\w.+-]*://)(?:[^\s/?#@:]*:[^\s?#]*|[^\s/?#@:]+)@";

/// `key=value`, `key: value`, `"key": "value"` for credential-bearing keys.
/// Case-insensitive; a plural key (`credentials:`) counts. The value is a double- or single-quoted string (spaces
/// included), an auth-scheme-prefixed credential, or one whitespace-free run.
const SECRET_PATTERN: &str = r#"(?i)((?:password|passwd|pwd|secret|token|dsn|api[_-]?key|authorization|cookie|credential|private[_-]?key)s?)(["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*"|'[^']*'|(?:(?:basic|bearer|digest|negotiate)\s+)?\S+)"#;

/// Explicit allowlist of env names whose **values** must never reach GlitchTip
/// (the file-header list). These keys carry hostnames or signing secrets that
/// the other regexes miss: a userinfo-less `STATE_DB_URL=…` leaks the
/// internal hostname, and `SESSION_SIGNING_KEY=…` matches no secret keyword.
/// Leading `\b` is zero-width, so `MY_STATE_DB_URL` (`_`→`S` is not a word
/// boundary) is left alone.
const SENSITIVE_KEY_PATTERN: &str = r"(?i)\b(STATE_DB_URL|TARGET_DB_URL|PERMISSIONS_DB_DSN|OIDC_CLIENT_SECRET|SESSION_SIGNING_KEY)\s*[:=]\s*\S+";

/// JSON object keys whose whole value is redacted regardless of its shape.
/// Compared against the key lowercased with every non-alphanumeric dropped, so
/// `api_key`, `Api-Key` and `apikey` are one entry; substring match, so
/// `access_token`, `x-api-key` and `set-cookie` are covered.
const SENSITIVE_JSON_KEYS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "dsn",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "privatekey",
    "statedburl",
    "targetdburl",
    "sessionsigningkey",
];

/// The scrubber could not be built. One failure mode only: a pattern that does
/// not compile under this build's `regex` features. Names the constant so the
/// operator does not have to diff the regexes against a feature list.
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
    service_token: Regex,
    jwt: Regex,
    bearer: Regex,
    url_creds: Regex,
    sensitive_key: Regex,
    secret: Regex,
}

impl Scrubber {
    /// Compile every pattern. The literals are static, so the only way this
    /// fails is a build whose `regex` features do not cover what they use
    /// (`unicode-case` for `(?i)`, `unicode-perl` for `\w`/`\s`/`\b`) — a
    /// dependency defect, surfaced at boot by [`super::init`].
    pub(super) fn new() -> Result<Self, ScrubberError> {
        Ok(Self {
            service_token: compile("SERVICE_TOKEN_PATTERN", SERVICE_TOKEN_PATTERN)?,
            jwt: compile("JWT_PATTERN", JWT_PATTERN)?,
            bearer: compile("BEARER_PATTERN", BEARER_PATTERN)?,
            url_creds: compile("URL_CREDS_PATTERN", URL_CREDS_PATTERN)?,
            sensitive_key: compile("SENSITIVE_KEY_PATTERN", SENSITIVE_KEY_PATTERN)?,
            secret: compile("SECRET_PATTERN", SECRET_PATTERN)?,
        })
    }

    /// Redact credentials in `s`.
    ///
    /// Self-identifying tokens go first (service tokens, JWTs, bearer values)
    /// so they are caught wherever they sit; then URL userinfo (so
    /// `dsn: postgres://u:p@h` loses `u:p` even though `dsn:` also matches a
    /// later pass); then the env-name allowlist (whole value); then `key=value`
    /// secrets by keyword. Each pass replaces only the secret *portion* — text
    /// that matches nothing comes back byte-identical.
    pub(super) fn scrub_str(&self, s: &str) -> String {
        let s = self.service_token.replace_all(s, REDACTED);
        let s = self.jwt.replace_all(&s, REDACTED);
        let s = self.bearer.replace_all(&s, format!("${{1}}{REDACTED}"));
        let s = self.url_creds.replace_all(&s, format!("${{1}}{REDACTED}@"));
        let s = self
            .sensitive_key
            .replace_all(&s, format!("${{1}}={REDACTED}"));
        self.secret
            .replace_all(&s, format!("${{1}}${{2}}{REDACTED}"))
            .into_owned()
    }

    /// Redact a JSON tree: the whole value under a sensitive key, every other
    /// string leaf (and object key) by pattern.
    pub(super) fn scrub_json(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.scrub_str(s),
            Value::Array(items) => items.iter_mut().for_each(|v| self.scrub_json(v)),
            Value::Object(map) => {
                let scrubbed: Map<String, Value> = std::mem::take(map)
                    .into_iter()
                    .map(|(key, mut v)| {
                        if is_sensitive_key(&key) {
                            redact_all(&mut v);
                        } else {
                            self.scrub_json(&mut v);
                        }
                        (self.scrub_str(&key), v)
                    })
                    .collect();
                *map = scrubbed;
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

/// Whether a JSON object key names a credential (see [`SENSITIVE_JSON_KEYS`]).
fn is_sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    SENSITIVE_JSON_KEYS
        .iter()
        .any(|needle| normalized.contains(needle))
}

/// Replace every string and number beneath `value` with the sentinel. The
/// shape (objects, arrays, null, bool) survives so typed protocol fields still
/// deserialise.
fn redact_all(value: &mut Value) {
    match value {
        Value::String(_) | Value::Number(_) => *value = Value::String(REDACTED.to_owned()),
        Value::Array(items) => items.iter_mut().for_each(redact_all),
        Value::Object(map) => map.values_mut().for_each(redact_all),
        Value::Null | Value::Bool(_) => {}
    }
}

/// Compile one named pattern, tagging a failure with the constant's name.
fn compile(name: &'static str, pattern: &str) -> Result<Regex, ScrubberError> {
    Regex::new(pattern).map_err(|source| ScrubberError { name, source })
}
