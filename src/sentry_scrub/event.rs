//! The `before_send` pass: which event fields get scrubbed.

use super::scrubber::Scrubber;

impl Scrubber {
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
    pub(super) fn scrub_event(
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
