//! Credential scrubbing for outgoing GlitchTip (Sentry-protocol) events.
//!
//! CLAUDE.md non-negotiable #1: DB DSNs/passwords must never leave the
//! gateway — not in responses, logs, errors, or admin endpoints. GlitchTip
//! ingest is an *external* network sink, so the same rule applies to every
//! event shipped there. The `before_send` hook registered in [`init`] runs on
//! the fully-assembled event (after the backtrace/contexts integrations have
//! populated it) and redacts anything that looks like a connection string or
//! a secret assignment *before* it hits the wire.
//!
//! Env keys whose **values** must never reach GlitchTip: `STATE_DB_URL`,
//! `TARGET_DB_URL`, `PERMISSIONS_DB_DSN`, `OIDC_CLIENT_SECRET`,
//! `SESSION_SIGNING_KEY`. These are matched by name against an explicit
//! allowlist ([`SENSITIVE_KEY_PATTERN`]) and their entire value redacted — so a
//! userinfo-less `STATE_DB_URL=postgres://db.internal/app` (whose internal
//! hostname the URL regex would leave intact) and a `SESSION_SIGNING_KEY=…`
//! (which matches neither `key`/`url`) are both covered. Beyond that,
//! URL-credential values are caught by the URL regex regardless of the key that
//! carried them, and `…_SECRET` / `…_DSN`-style assignments are caught by the
//! secret-keyword regex. This is defense in depth on top of the gateway's
//! primary rule (credentials never travel in errors/logs) — the scrubber exists
//! for the day something slips past that.
//!
//! The three patterns are compiled **once, at boot**, by [`Scrubber::new`]. A
//! pattern that does not compile aborts the process instead of degrading: the
//! previous shape compiled them lazily and substituted the redaction sentinel
//! for the whole string when compilation failed, which silently destroyed every
//! field of every event for a month (see the `unicode-case` note on the `regex`
//! dependency in `Cargo.toml`). A scrubber that cannot scrub is a build defect,
//! not a runtime condition, and it must be impossible to ship quietly.
//!
//! Error tracking **only**: [`init`] pins `traces_sample_rate` to `0.0`.
//! GlitchTip cannot ingest transactions/spans/replay, so any perf data would
//! be silently dropped or mis-stored.

use std::sync::Arc;

use regex::Regex;
use sentry::types::Dsn;
use sentry::{ClientInitGuard, ClientOptions};

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

/// The compiled patterns, owned by the `before_send` hook for the life of the
/// process. Construction is the only place compilation can fail, so every
/// method below is total — there is no "scrubber that might not work" state to
/// branch on at send time.
struct Scrubber {
    url_creds: Regex,
    sensitive_key: Regex,
    secret: Regex,
}

impl Scrubber {
    /// Compile the three patterns. The literals are static, so the only way
    /// this fails is a build whose `regex` features do not cover what they use
    /// (`unicode-case` for `(?i)`, `unicode-perl` for `\w`/`\s`/`\b`) — a
    /// dependency defect, surfaced at boot by [`init`].
    fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            url_creds: Regex::new(URL_CREDS_PATTERN)?,
            sensitive_key: Regex::new(SENSITIVE_KEY_PATTERN)?,
            secret: Regex::new(SECRET_PATTERN)?,
        })
    }

    /// Redact connection-string credentials and secret assignments in `s`.
    ///
    /// Applied in three passes: URL userinfo first (so `dsn: postgres://u:p@h`
    /// loses `u:p` even though `dsn:…` also matches a later pass), then the
    /// sensitive-key allowlist (whole-value redact for the named env keys),
    /// then `key=value` secrets by keyword. Each pass replaces only the secret
    /// *portion* — text that matches nothing comes back byte-identical.
    fn scrub_str(&self, s: &str) -> String {
        let after_url = self.url_creds.replace_all(s, format!("$1{REDACTED}@"));
        let after_key = self
            .sensitive_key
            .replace_all(&after_url, format!("$1={REDACTED}"));
        self.secret
            .replace_all(&after_key, format!("$1={REDACTED}"))
            .into_owned()
    }

    /// Recursively redact every JSON string leaf.
    fn scrub_json(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => *s = self.scrub_str(s),
            serde_json::Value::Array(items) => items.iter_mut().for_each(|v| self.scrub_json(v)),
            serde_json::Value::Object(map) => map.values_mut().for_each(|v| self.scrub_json(v)),
            _ => {}
        }
    }

    /// `before_send`: scrub every credential-bearing string on the event, then
    /// pass it through. Returns `Some` always — we redact, never drop.
    ///
    /// Fields touched (the ones that can carry operator- or driver-injected text):
    /// - [`sentry::protocol::Event::message`] — the free-form message.
    /// - each `exception.values[].value` (the rendered error message) **and** the
    ///   exception `ty` (class name) — both per the goal "exception values/type".
    /// - each `breadcrumbs.values[].message` plus every string leaf in its `data` map.
    /// - `tags` (every value), `user` (`id` / `email` / `username` string fields plus
    ///   the forwards-compat `other` JSON map), and `request` (`url`, `method`,
    ///   `data`, `query_string`, `cookies`, plus the `headers` / `env` string maps).
    ///   `send_default_pii: false` only suppresses SDK *auto*-PII; anything manually
    ///   attached to these fields must still be scrubbed.
    /// - every [`serde_json::Value::String`] reachable in `extra` (nested maps and
    ///   arrays walked recursively).
    /// - every value in `Context::Other` maps under `contexts`.
    fn scrub_event(
        &self,
        mut event: sentry::protocol::Event<'static>,
    ) -> Option<sentry::protocol::Event<'static>> {
        if let Some(msg) = event.message.as_mut() {
            *msg = self.scrub_str(msg);
        }

        for ex in event.exception.values.iter_mut() {
            ex.ty = self.scrub_str(&ex.ty);
            if let Some(val) = ex.value.as_mut() {
                *val = self.scrub_str(val);
            }
        }

        for bc in event.breadcrumbs.values.iter_mut() {
            if let Some(msg) = bc.message.as_mut() {
                *msg = self.scrub_str(msg);
            }
            // `Breadcrumb::data` (`Map<String, Value>`) carries arbitrary nested
            // JSON (HTTP method/url, query params, custom state). Same scrubber as
            // `extra` / `Context::Other` — a secret in `data` must not slip past.
            for value in bc.data.values_mut() {
                self.scrub_json(value);
            }
        }

        // `extra` and `Context::Other` hold arbitrary JSON; walk to every string leaf.
        for value in event.extra.values_mut() {
            self.scrub_json(value);
        }
        for ctx in event.contexts.values_mut() {
            if let sentry::protocol::Context::Other(map) = ctx {
                for value in map.values_mut() {
                    self.scrub_json(value);
                }
            }
        }

        // `tags` is a flat string->string map. Operator-set tags can carry secrets;
        // `send_default_pii: false` does not touch them. Scrub every value.
        for value in event.tags.values_mut() {
            *value = self.scrub_str(value);
        }

        // `user` and `request` hold *manually*-attached data (`send_default_pii`
        // only suppresses SDK auto-PII), so scrub their free-text string fields with
        // the same `scrub_str`, and any forwards-compat JSON map with `scrub_json`.
        if let Some(user) = event.user.as_mut() {
            if let Some(id) = user.id.as_mut() {
                *id = self.scrub_str(id);
            }
            if let Some(email) = user.email.as_mut() {
                *email = self.scrub_str(email);
            }
            if let Some(username) = user.username.as_mut() {
                *username = self.scrub_str(username);
            }
            // `ip_address` is a typed IP, not free text — nothing to scrub.
            for value in user.other.values_mut() {
                self.scrub_json(value);
            }
        }

        if let Some(req) = event.request.as_mut() {
            // `url` is a typed `Url`, not a `String`: round-trip through the string
            // scrubber and reparse. If the scrubbed form no longer parses, drop it
            // (`ok()` -> `None`) rather than risk shipping an unscrubbed URL.
            if let Some(url) = req.url.take() {
                req.url = self.scrub_str(url.as_str()).parse().ok();
            }
            if let Some(method) = req.method.as_mut() {
                *method = self.scrub_str(method);
            }
            if let Some(data) = req.data.as_mut() {
                *data = self.scrub_str(data);
            }
            if let Some(query) = req.query_string.as_mut() {
                *query = self.scrub_str(query);
            }
            if let Some(cookies) = req.cookies.as_mut() {
                *cookies = self.scrub_str(cookies);
            }
            for value in req.headers.values_mut() {
                *value = self.scrub_str(value);
            }
            for value in req.env.values_mut() {
                *value = self.scrub_str(value);
            }
        }

        Some(event)
    }
}

/// Initialize the global GlitchTip client and return a guard that must live
/// for the entire program (it flushes the send queue on drop).
///
/// Fails only when the scrubber's patterns do not compile in this build — the
/// caller turns that into a boot abort, because an event stream that cannot be
/// scrubbed must never be opened.
///
/// DSN comes from `SENTRY_DSN`; an unset, empty, or malformed value yields a
/// **disabled** client — the app still runs, nothing is shipped. `SENTRY_ENVIRONMENT`
/// falls back to `"development"`. The release is pinned to the crate version
/// (not read from env) so the field is stable and operator-independent.
///
/// The returned [`ClientInitGuard`] is `#[must_use]` for a reason: dropping it
/// early flushes-and-shuts the transport. The caller binds it to a name that
/// outlives the runtime.
pub(crate) fn init() -> Result<ClientInitGuard, regex::Error> {
    // Compile before anything can be captured: the client is only opened once
    // every outgoing event is guaranteed to pass through a working scrubber.
    let scrubber = Scrubber::new()?;

    let dsn = std::env::var("SENTRY_DSN")
        .ok()
        .and_then(|raw| parse_dsn(&raw));
    let environment = std::env::var("SENTRY_ENVIRONMENT")
        .ok()
        .filter(|env| !env.is_empty())
        .unwrap_or_else(|| "development".to_owned());

    // The field is `Option<Arc<dyn Fn(Event) -> Option<Event> + Send + Sync>>`.
    // Bind the trait object at a typed let-site so the closure→trait-object
    // coercion resolves there, not at the struct-literal field (avoids relying
    // on the field-position coercion site).
    let before_send: Arc<
        dyn Fn(sentry::protocol::Event<'static>) -> Option<sentry::protocol::Event<'static>>
            + Send
            + Sync,
    > = Arc::new(move |event| scrubber.scrub_event(event));

    let opts = ClientOptions {
        dsn,
        environment: Some(environment.into()),
        release: Some(env!("CARGO_PKG_VERSION").into()),
        send_default_pii: false,
        // GlitchTip has no tracing/profiling/replay ingest; keep it off.
        traces_sample_rate: 0.0,
        before_send: Some(before_send),
        ..ClientOptions::default()
    };

    Ok(sentry::init(opts))
}

/// Parse a raw DSN string the way [`init`] does: empty/whitespace/malformed →
/// `None`. Pulled out of [`init`] so it can be unit-tested without touching the
/// process-wide `SENTRY_DSN` env var (which would race with parallel tests —
/// `std::env` is process-global, not thread-local).
fn parse_dsn(raw: &str) -> Option<Dsn> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<Dsn>().ok()
}

#[cfg(test)]
mod tests {
    //! No network, no real DB. Scrubber is pure string work, and DSN parsing
    //! is exercised via the pure [`parse_dsn`] helper → no test mutates the
    //! process env → parallel-safe.
    //!
    //! These run under `cargo test`, whose dependency graph includes
    //! dev-dependencies and therefore more `regex` features than the shipping
    //! binary gets. That is exactly how the fail-closed bug stayed green here
    //! while production redacted every event, so the *feature* half of this
    //! contract is enforced outside cargo test, by `bin/lint`.

    use super::*;

    fn scrubber() -> Scrubber {
        Scrubber::new().expect("scrubber patterns compile")
    }

    #[test]
    fn scrubs_postgres_dsn_in_event_message() {
        let secret = "app-dev-only";
        let mut event = sentry::protocol::Event {
            message: Some(format!(
                "connect postgres://app:{secret}@localhost:5434/app failed"
            )),
            ..sentry::protocol::Event::default()
        };
        // Same secret nested in `extra` JSON must also be caught by recursion.
        event.extra.insert(
            "ctx".to_owned(),
            serde_json::json!({ "url": format!("postgresql://app:{secret}@db:5432/x") }),
        );

        let scrubbed = scrubber()
            .scrub_event(event)
            .expect("scrubber always returns Some");
        let msg = scrubbed.message.as_deref().expect("message preserved");
        assert!(msg.contains("***REDACTED***"), "message redacted: {msg}");
        assert!(!msg.contains(secret), "password leaked into message: {msg}");

        let extra = scrubbed.extra.get("ctx").expect("extra preserved");
        let json = extra.to_string();
        assert!(json.contains("***REDACTED***"), "nested extra redacted");
        assert!(!json.contains(secret), "secret in nested extra");
    }

    #[test]
    fn scrubs_password_assignment() {
        let scrubber = scrubber();

        // `key=value` form (the contract under test).
        let out = scrubber.scrub_str("password=hunter2 ok");
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(!out.contains("hunter2"), "{out}");

        // `key: value` form, mixed case.
        let out = scrubber.scrub_str("OIDC_CLIENT_SECRET: s3cr3t-value");
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(!out.contains("s3cr3t-value"), "{out}");

        // Allowlisted env names: value redacted even with no `user:pass@`
        // userinfo and no secret keyword. The internal hostname must not leak.
        // (CodeRabbit: SESSION_SIGNING_KEY / STATE_DB_URL bypassed the old
        // scrubber.)
        let out = scrubber.scrub_str("SESSION_SIGNING_KEY=jwt-hs256-base64-secret");
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(!out.contains("jwt-hs256-base64-secret"), "{out}");

        let out = scrubber.scrub_str("STATE_DB_URL=postgres://db.internal/app");
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(
            !out.contains("db.internal"),
            "internal hostname leaked: {out}"
        );

        // A userinfo-bearing STATE_DB_URL is also fully redacted (allowlist
        // whole-value pass, not just the URL userinfo strip).
        let out = scrubber.scrub_str("STATE_DB_URL=postgres://app:s3cr3t@db.internal/app");
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(!out.contains("s3cr3t"), "{out}");
        assert!(!out.contains("db.internal"), "{out}");

        // `: value` separator, mixed case, and a sibling non-sensitive key
        // left intact.
        let out = scrubber.scrub_str("state_db_url: postgres://db.internal/app ok=1");
        assert!(out.contains("***REDACTED***"), "{out}");
        assert!(out.contains("ok=1"), "benign sibling key clobbered: {out}");

        // `MY_STATE_DB_URL` is not the allowlisted key — left alone by this
        // pass (its value carries no creds here).
        let out = scrubber.scrub_str("MY_STATE_DB_URL=harmless");
        assert!(!out.contains("***REDACTED***"), "false positive: {out}");

        // Each DB scheme family loses its userinfo, host stays.
        for raw in [
            "postgres://u:p@h/db",
            "postgresql://u:p@h:5432/db",
            "mysql://u:p@h/db",
            "mongodb://u:p@h/db",
            "mongodb+srv://u:p@cluster.h/db",
            "mariadb://u:p@h/db",
            "redis://u:p@h:6379",
        ] {
            let out = scrubber.scrub_str(raw);
            assert!(out.contains("***REDACTED***"), "{raw} -> {out}");
            assert!(!out.contains(":p@"), "userinfo leaked: {raw} -> {out}");
        }
    }

    #[test]
    fn does_not_redact_benign_text() {
        let scrubber = scrubber();
        // No creds, no secret keys → untouched.
        let raw = "query returned 42 rows from table users in 3ms";
        assert_eq!(scrubber.scrub_str(raw), raw);
        // A URL without credentials is left intact.
        let raw = "see https://example.com/docs for details";
        assert_eq!(scrubber.scrub_str(raw), raw);
    }

    /// The production regression (GlitchTip issue DB-MCP-GATEWAY-2, 40 events,
    /// every one titled `***REDACTED***: ***REDACTED***`): the whole string
    /// must never collapse to the sentinel. A scrubber that redacts everything
    /// leaks nothing but tells nobody anything, and every distinct error
    /// fingerprints into one unreadable issue.
    #[test]
    fn benign_error_text_never_collapses_to_the_sentinel() {
        let scrubber = scrubber();
        let boot_error = "state DB: failed to connect (io/ConnectionRefused; DSN withheld)";

        let mut event = sentry::protocol::Event::default();
        event.exception.values.push(sentry::protocol::Exception {
            ty: "Error".to_owned(),
            value: Some(boot_error.to_owned()),
            ..Default::default()
        });

        let scrubbed = scrubber.scrub_event(event).expect("Some");
        let ex = &scrubbed.exception.values[0];
        assert_eq!(ex.ty, "Error", "exception type replaced wholesale");
        assert_eq!(
            ex.value.as_deref(),
            Some(boot_error),
            "exception value replaced wholesale"
        );
    }

    #[test]
    fn scrubs_exception_value_and_type() {
        let mut event = sentry::protocol::Event::default();
        event.exception.values.push(sentry::protocol::Exception {
            ty: "ConnectError postgres://u:leak-me@h/db".to_owned(),
            value: Some("dsn=postgres://u:leak-me@h/db".into()),
            ..Default::default()
        });

        let scrubbed = scrubber().scrub_event(event).expect("Some");
        let ex = &scrubbed.exception.values[0];
        assert!(!ex.ty.contains("leak-me"), "type leaked: {}", ex.ty);
        let val = ex.value.as_deref().expect("value preserved");
        assert!(!val.contains("leak-me"), "value leaked: {val}");
        assert!(ex.ty.contains("***REDACTED***"));
    }

    /// Raw sentry crate is a no-op with no DSN — the invariant [`init()`]
    /// relies on (`is_enabled` gates on `options.dsn.is_some()`).
    #[test]
    fn client_disabled_when_dsn_unset() {
        let guard = sentry::init(sentry::ClientOptions {
            dsn: None,
            ..Default::default()
        });
        assert!(!guard.is_enabled(), "client with no DSN must be disabled");
    }

    #[test]
    fn scrubs_breadcrumb_data() {
        // `Breadcrumb::data` is `Map<String, Value>` — arbitrary nested JSON.
        // A connection string nested in there must be walked and redacted, not
        // just the breadcrumb `message`.
        let secret = "hunter2";
        let mut bc = sentry::protocol::Breadcrumb {
            message: Some(format!("connecting as password={secret}")),
            ..sentry::protocol::Breadcrumb::default()
        };
        bc.data.insert(
            "url".to_owned(),
            serde_json::json!(format!("postgres://app:{secret}@db:5432/app")),
        );
        bc.data.insert(
            "nested".to_owned(),
            serde_json::json!({ "auth": format!("dsn: postgres://app:{secret}@db/x") }),
        );

        let mut event = sentry::protocol::Event::default();
        event.breadcrumbs.values.push(bc);

        let scrubbed = scrubber()
            .scrub_event(event)
            .expect("scrubber always returns Some");
        let out = &scrubbed.breadcrumbs.values[0];

        // `message` redacted.
        let msg = out.message.as_deref().expect("message preserved");
        assert!(
            !msg.contains(secret),
            "secret leaked into breadcrumb message: {msg}"
        );

        // Each data value walked to its string leaves.
        let url = out.data.get("url").expect("url preserved").to_string();
        assert!(
            url.contains("***REDACTED***"),
            "breadcrumb data url redacted: {url}"
        );
        assert!(
            !url.contains(secret),
            "secret leaked into breadcrumb data url: {url}"
        );

        let nested = out
            .data
            .get("nested")
            .expect("nested preserved")
            .to_string();
        assert!(
            nested.contains("***REDACTED***"),
            "nested breadcrumb data redacted: {nested}"
        );
        assert!(
            !nested.contains(secret),
            "secret leaked into nested breadcrumb data: {nested}"
        );
    }

    #[test]
    fn scrubs_tags_user_and_request() {
        // Manually-attached tag/user/request data can carry secrets even with
        // `send_default_pii: false` (that only drops SDK auto-PII). A secret
        // placed in any of these fields must be redacted, not shipped.
        let secret = "hunter2";
        let mut event = sentry::protocol::Event::default();

        // tags: flat string->string map.
        event
            .tags
            .insert("db".to_owned(), format!("postgres://app:{secret}@db/app"));
        event
            .tags
            .insert("note".to_owned(), format!("password={secret}"));

        // user: string fields + the forwards-compat `other` map.
        event.user = Some(sentry::protocol::User {
            id: Some(format!("dsn=postgres://app:{secret}@db/app")),
            email: Some(format!("token={secret}")),
            username: Some(format!("secret={secret}")),
            other: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    "profile".to_owned(),
                    serde_json::json!({ "url": format!("mysql://app:{secret}@h/db") }),
                );
                m
            },
            ..Default::default()
        });

        // request: string fields, the url, and the header/env string maps.
        let mut request = sentry::protocol::Request {
            url: format!("https://app:{secret}@host/path").parse().ok(),
            method: Some("POST".to_owned()),
            data: Some(format!("dsn: postgres://app:{secret}@db/x")),
            query_string: Some(format!("token={secret}")),
            cookies: Some(format!("session=abc; secret={secret}")),
            ..Default::default()
        };
        request
            .headers
            .insert("Authorization".to_owned(), format!("secret={secret}"));
        request.env.insert(
            "STATE_DB_URL".to_owned(),
            format!("postgres://app:{secret}@db/app"),
        );
        event.request = Some(request);

        let scrubbed = scrubber()
            .scrub_event(event)
            .expect("scrubber always returns Some");

        // Serialize the whole event: proves no secret leaks through *any* of the
        // newly-scrubbed fields, and that redaction actually fired.
        let json = serde_json::to_string(&scrubbed).expect("event serializes");
        assert!(
            !json.contains(secret),
            "secret leaked into tags/user/request: {json}"
        );
        assert!(
            json.contains("***REDACTED***"),
            "expected redaction marker in scrubbed event: {json}"
        );

        // Spot-check each field individually so a regression narrows to a field.
        let scrubbed_tags = &scrubbed.tags;
        assert!(!scrubbed_tags["db"].contains(secret), "tag value leaked");
        assert!(!scrubbed_tags["note"].contains(secret), "tag value leaked");

        let user = scrubbed.user.as_ref().expect("user preserved");
        assert!(
            !user.id.as_deref().unwrap().contains(secret),
            "user.id leaked"
        );
        assert!(
            !user.email.as_deref().unwrap().contains(secret),
            "user.email leaked"
        );
        assert!(
            !user.username.as_deref().unwrap().contains(secret),
            "user.username leaked"
        );
        assert!(
            !user.other["profile"].to_string().contains(secret),
            "user.other leaked"
        );

        let req = scrubbed.request.as_ref().expect("request preserved");
        // url either redacted in place or dropped — either way the secret is gone.
        if let Some(url) = req.url.as_ref() {
            assert!(!url.as_str().contains(secret), "request.url leaked: {url}");
        }
        assert!(
            !req.data.as_deref().unwrap().contains(secret),
            "request.data leaked"
        );
        assert!(
            !req.query_string.as_deref().unwrap().contains(secret),
            "request.query_string leaked"
        );
        assert!(
            !req.cookies.as_deref().unwrap().contains(secret),
            "request.cookies leaked"
        );
        assert!(
            !req.headers["Authorization"].contains(secret),
            "request header leaked"
        );
        assert!(
            !req.env["STATE_DB_URL"].contains(secret),
            "request env leaked"
        );
    }

    /// `init()`'s DSN parsing, tested on a pure helper instead of mutating the
    /// process-wide `SENTRY_DSN` (CodeRabbit: `set_var`/`remove_var` racy under
    /// parallel test threads). Empty/whitespace/malformed → `None` (disabled).
    #[test]
    fn parse_dsn_rejects_empty_and_malformed() {
        assert_eq!(parse_dsn(""), None, "empty -> disabled");
        assert_eq!(parse_dsn("   "), None, "whitespace -> disabled");
        assert_eq!(parse_dsn("not-a-valid-dsn"), None, "malformed -> disabled");
    }
}
