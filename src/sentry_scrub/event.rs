//! The `before_send` pass over a whole event.

use sentry::protocol::Event;

use super::scrubber::Scrubber;

impl Scrubber {
    /// `before_send`: serialise the event to JSON, scrub every string leaf and
    /// every value under a sensitive key in one walk, deserialise.
    ///
    /// Walking the serialised form covers every field the protocol has —
    /// `message`, `logentry`, `culprit`, `transaction`, `fingerprint`,
    /// `exception[].{type,value,module,mechanism.data}`, stack-frame `vars`,
    /// breadcrumbs, tags, `user`, `request` (headers, cookies, env), `extra`,
    /// contexts — including fields a future sentry release adds, instead of a
    /// hand-kept list that silently misses the next one.
    ///
    /// Fails closed: an event that cannot round-trip is **dropped**, never
    /// shipped unscrubbed.
    pub(super) fn scrub_event(&self, event: Event<'static>) -> Option<Event<'static>> {
        let mut json = serde_json::to_value(&event).ok()?;
        self.scrub_json(&mut json);
        serde_json::from_value(json).ok()
    }
}
