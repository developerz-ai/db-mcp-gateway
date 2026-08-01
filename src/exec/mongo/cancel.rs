//! Best-effort server-side cancellation for the mongo adapter (#141).
//!
//! Postgres has `pg_cancel_backend(pid)`: the pid is known before the query
//! starts and cancelling your own backend needs no extra privilege. Mongo has
//! no equivalent primitive reachable from this driver — the only route is
//! `currentOp` + `killOp`, and both come with real constraints:
//!
//! - `comment` on an arbitrary command (the only way to correlate a
//!   `currentOp` entry back to *this* request) requires MongoDB **4.4+**.
//!   The gateway's minimum supported Mongo version is 4.4 — see
//!   `config-reference.md` §Mongo.
//! - Cancellation needs TWO cluster-admin actions, neither of which belongs
//!   to a least-privilege read-only role: `inprog` (for the `currentOp`
//!   lookup, which uses `$ownOps: false`) and `killop`. The built-in
//!   `clusterManager` role covers both. Operators who want mongo
//!   cancellation must grant them explicitly on the gateway's mongo role;
//!   deployment docs call this out. Without them, the lookup or `killOp`
//!   fails, the guard logs a warning, and `maxTimeMS` remains the only
//!   bound — identical to pre-#141 behavior.
//! - The lookup is inherently best-effort: `currentOp` is polled once, after
//!   the drop fires, and races the operation's own registration. A very
//!   short-lived operation may already be gone by the time we look. This is
//!   an accepted trade-off (YAGNI: don't build a polling loop for a gap this
//!   narrow) — `maxTimeMS` remains the hard backstop either way, exactly as
//!   it did before this module existed.

use mongodb::Client;
use mongodb::bson::{Bson, Document, doc};
use tracing::Instrument;
use uuid::Uuid;

/// Stamp a unique `comment` on `cmd` and return the marker. Unconditional
/// overwrite — same rationale as the `maxTimeMS` stamp in `dispatch`: a
/// caller-supplied `comment` could otherwise collide with (or spoof) the
/// marker this module searches for in `currentOp`.
pub fn stamp_marker(cmd: &mut Document) -> String {
    let marker = Uuid::new_v4().to_string();
    cmd.insert("comment", marker.clone());
    marker
}

/// Fires `currentOp` + `killOp` from a detached task if dropped while armed —
/// the mongo analogue of `pg::CancelOnDrop`. See module docs for why this is
/// best-effort rather than a guarantee.
///
/// Disarmed on the normal path once the command has run to completion, so a
/// cleanly-finished operation is never targeted.
pub struct KillOpOnDrop {
    /// `Some` while armed: the client (to open the admin-db connection) and
    /// the marker stamped on this request's command.
    armed: Option<(Client, String)>,
}

impl std::fmt::Debug for KillOpOnDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never derive: `mongodb::Client`'s own `Debug` renders the parsed
        // `ClientOptions` including credentials, and the marker is a
        // request-scoped token used to authenticate a `killOp` against this
        // exact operation. Structural info only — same posture as
        // `MongoAdapter::Debug`.
        f.debug_struct("KillOpOnDrop")
            .field("armed", &self.armed.is_some())
            .finish()
    }
}

impl KillOpOnDrop {
    pub fn armed(client: Client, marker: String) -> Self {
        Self {
            armed: Some((client, marker)),
        }
    }

    pub fn disarm(&mut self) {
        self.armed = None;
    }
}

impl Drop for KillOpOnDrop {
    fn drop(&mut self) {
        let Some((client, marker)) = self.armed.take() else {
            return;
        };
        // `Drop` can run outside a runtime context (runtime teardown, or a
        // test dropping the future after the runtime ends). `tokio::spawn`
        // panics there, and CLAUDE.md forbids panics on the hot path; a
        // panic during unwind is also an abort. Best-effort means "skip",
        // not "abort".
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("no tokio runtime at drop; skipping mongo killOp");
            return;
        };
        // Inherit the dispatch span so `request_id`, `user`, `server`, and
        // `database` reach the warn lines below — the detached task starts
        // with no parent otherwise, and an operator seeing "killOp failed"
        // could not map it back to a request.
        let span = tracing::Span::current();
        // Detached: the parent future is being dropped, so we can't await
        // inline. Runs on a fresh task independent of the dropped future.
        handle.spawn(
            async move {
                let admin = client.database("admin");
                let opids = find_opids_by_marker(&admin, &marker).await;
                for opid in opids {
                    if let Err(err) = admin.run_command(doc! { "killOp": 1, "op": opid }).await {
                        // `killOp` commonly fails with "unauthorized" when
                        // the role lacks the privilege documented in the
                        // module docs — that is an expected, not
                        // exceptional, outcome for operators who haven't
                        // opted in. Warn, don't error: `maxTimeMS` is still
                        // the backstop. Log only the driver's error
                        // category — never `%err`, whose `Display` can
                        // surface `Authentication` / `ServerSelection`
                        // messages carrying credentials or hostnames
                        // (CLAUDE.md `src/exec/**` redaction rule).
                        tracing::warn!(
                            error_kind = classify_mongo_error(&err),
                            "killOp failed during mongo cancel (missing privilege, or op already finished)"
                        );
                    }
                }
            }
            .instrument(span),
        );
    }
}

/// Category label for a `mongodb::Error` — safe to log. The driver's
/// `Display` and `Debug` can surface authentication messages, server-selection
/// details, and other operator-sensitive context; only the `ErrorKind`
/// variant name goes to `tracing`. `ErrorKind` is `#[non_exhaustive]`, so the
/// catch-all is required.
fn classify_mongo_error(err: &mongodb::error::Error) -> &'static str {
    use mongodb::error::ErrorKind;
    match err.kind.as_ref() {
        ErrorKind::Authentication { .. } => "authentication",
        ErrorKind::Command(_) => "command",
        ErrorKind::Io(_) => "io",
        ErrorKind::ConnectionPoolCleared { .. } => "pool_cleared",
        ErrorKind::DnsResolve { .. } => "dns_resolve",
        ErrorKind::ServerSelection { .. } => "server_selection",
        _ => "other",
    }
}

/// Look up every `opid` of an in-progress operation carrying `marker` as its
/// `command.comment`. Returns an empty vec on any lookup failure or if
/// nothing matched — both are expected outcomes (see module docs), not
/// exceptions to propagate.
///
/// Iterates every `inprog` entry rather than picking the first: a `mongos`
/// fan-out surfaces one entry per shard for the same request, and each
/// entry carries its own shard-local `opid` that must be killed individually.
async fn find_opids_by_marker(admin: &mongodb::Database, marker: &str) -> Vec<Bson> {
    let Ok(response) = admin
        .run_command(doc! {
            "currentOp": 1,
            "$ownOps": false,
            "command.comment": marker,
        })
        .await
        .inspect_err(|err| {
            tracing::warn!(
                error_kind = classify_mongo_error(err),
                "currentOp lookup failed during mongo cancel"
            );
        })
    else {
        return Vec::new();
    };
    let Ok(inprog) = response.get_array("inprog") else {
        return Vec::new();
    };
    inprog
        .iter()
        .filter_map(|entry| {
            let Bson::Document(doc) = entry else {
                return None;
            };
            doc.get("opid").cloned()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_marker_inserts_comment_and_returns_it() {
        let mut cmd = doc! { "find": "users" };
        let marker = stamp_marker(&mut cmd);
        assert_eq!(cmd.get_str("comment").unwrap(), marker);
        // Sanity: markers are actually unique, not a constant placeholder.
        let mut cmd2 = doc! { "find": "users" };
        let marker2 = stamp_marker(&mut cmd2);
        assert_ne!(marker, marker2);
    }

    /// A caller-supplied `comment` must never survive the stamp — otherwise
    /// it could collide with (or be crafted to match) another request's
    /// marker and confuse the currentOp lookup.
    #[test]
    fn stamp_marker_overwrites_existing_comment() {
        let mut cmd = doc! { "find": "users", "comment": "caller-supplied" };
        let marker = stamp_marker(&mut cmd);
        assert_eq!(cmd.get_str("comment").unwrap(), marker);
        assert_ne!(marker, "caller-supplied");
    }

    /// `disarm()` must prevent the detached spawn on drop. `Client::with_options`
    /// never opens a connection until first use (same posture as `mod.rs`'s
    /// own tests), so this is safe to construct without a real mongo
    /// instance — the assertion is just that `armed` is `None` after
    /// `disarm()`, which is what `Drop::drop` checks before spawning.
    #[tokio::test]
    async fn disarm_prevents_drop_from_spawning() {
        use mongodb::options::{ClientOptions, ServerAddress};

        let options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: "localhost".to_string(),
                port: Some(27017),
            }])
            .build();
        let client = Client::with_options(options).expect("client constructs");

        let mut guard = KillOpOnDrop::armed(client, "unused-marker".to_string());
        assert!(guard.armed.is_some());
        guard.disarm();
        assert!(guard.armed.is_none());
        // Drop now runs with `armed == None` — `Drop::drop`'s `let Some(...)
        // = ... else { return }` returns immediately, no spawn.
    }

    /// `Debug` must never leak the mongo client (credentials in
    /// `ClientOptions`) or the request-scoped marker. Mirrors
    /// `MongoAdapter::debug_does_not_leak_credentials`.
    #[tokio::test]
    async fn debug_does_not_leak_client_or_marker() {
        use mongodb::options::{ClientOptions, ServerAddress};

        let options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: "leak-host".to_string(),
                port: Some(27017),
            }])
            .build();
        let client = Client::with_options(options).expect("client constructs");
        let marker = "leak-marker-should-not-appear";
        let guard = KillOpOnDrop::armed(client, marker.to_string());
        let rendered = format!("{guard:?}");
        assert!(rendered.contains("armed"));
        assert!(!rendered.contains(marker), "leaked marker: {rendered}");
        assert!(!rendered.contains("leak-host"), "leaked host: {rendered}");
    }
}
