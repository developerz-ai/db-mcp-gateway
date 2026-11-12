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
//! What is redacted, by value anywhere in the event: bare service tokens
//! (`dbmcp_svc_…`), JWTs, `Bearer …` credentials, URL userinfo (including
//! password-only and passwords containing `/` or `@`), `key=value` /
//! `"key":"value"` assignments for credential keywords (quoted values with
//! spaces included), and the whole value of the env keys `STATE_DB_URL`,
//! `TARGET_DB_URL`, `PERMISSIONS_DB_DSN`, `OIDC_CLIENT_SECRET`,
//! `SESSION_SIGNING_KEY`. By key: every value under a JSON object key that
//! names a credential (`password`, `token`, `authorization`, `cookie`, …),
//! whatever its shape. The event is serialised, walked once and deserialised,
//! so every protocol field is covered — not a hand-kept list. This is defense
//! in depth on top of the gateway's primary rule (credentials never travel in
//! errors/logs) — the scrubber exists for the day something slips past that.
//!
//! The patterns are compiled **once, at boot**, by [`scrubber::Scrubber::new`]. A
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

mod event;
mod scrubber;

use std::sync::Arc;

use sentry::types::Dsn;
use sentry::{ClientInitGuard, ClientOptions, TracesSamplingStrategy};

use scrubber::{Scrubber, ScrubberError};

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
pub(crate) fn init() -> Result<ClientInitGuard, ScrubberError> {
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

    // `ClientOptions` is `#[non_exhaustive]` since sentry 0.49, so it is built
    // by assignment rather than a struct literal.
    let mut opts = ClientOptions::default();
    opts.dsn = dsn;
    opts.environment = Some(environment.into());
    opts.release = Some(env!("CARGO_PKG_VERSION").into());
    opts.send_default_pii = false;
    // GlitchTip has no tracing/profiling/replay ingest; keep it off.
    opts.traces_sampling_strategy = TracesSamplingStrategy::Disabled;
    opts.before_send = Some(before_send);

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
mod tests;
