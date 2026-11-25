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

use std::time::Duration;

use mongodb::Client;
use mongodb::bson::{Bson, Document, doc};
use tokio::sync::OwnedSemaphorePermit;
use tracing::Instrument;
use uuid::Uuid;

use crate::audit::drain::DetachedTasks;

/// Longest a detached cancel may keep the command's [`Reservation`]. Below
/// the 5 s acquire wait, so a caller queued behind a stuck cancel still gets
/// its connection. Dropping a stuck cancel closes the connection it was on.
const CANCEL_BOUND: Duration = Duration::from_secs(3);

/// What one command holds of the pool while it runs: a connection, and its
/// caller's share of them.
#[derive(Debug)]
pub struct Reservation {
    // Declared first, so a connection is free before its caller's share is.
    pub(super) _connection: OwnedSemaphorePermit,
    pub(super) _slot: Option<OwnedSemaphorePermit>,
}

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
    /// Where the detached kill runs, so a shutdown drain waits for it.
    detached: DetachedTasks,
    /// The command's own reservation; the kill inherits it rather than
    /// taking one. The dropped command's connection is closed, so the kill
    /// finds that connection's place in the pool free and can never wait on
    /// the commands it is freeing; released here instead, the next command's
    /// checkout would wait on the kill inside its own statement budget.
    reservation: Option<Reservation>,
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
    pub fn armed(
        client: Client,
        marker: String,
        detached: DetachedTasks,
        reservation: Reservation,
    ) -> Self {
        Self {
            armed: Some((client, marker)),
            detached,
            reservation: Some(reservation),
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
        // test dropping the future after the runtime ends). Spawning panics
        // there, and CLAUDE.md forbids panics on the hot path; a
        // panic during unwind is also an abort. Best-effort means "skip",
        // not "abort".
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::warn!("no tokio runtime at drop; skipping mongo killOp");
            return;
        }
        // Inherit the dispatch span so `request_id`, `user`, `server`, and
        // `database` reach the warn lines below — the detached task starts
        // with no parent otherwise, and an operator seeing "killOp failed"
        // could not map it back to a request.
        let span = tracing::Span::current();
        let reservation = self.reservation.take();
        // Detached: the parent future is being dropped, so we can't await
        // inline. Runs on a fresh, tracked task independent of the dropped
        // future.
        self.detached.spawn(
            async move {
                let kill = kill_ops_by_marker(&client, &marker);
                if tokio::time::timeout(CANCEL_BOUND, kill).await.is_err() {
                    tracing::warn!("mongo cancel gave up: no answer within its bound");
                }
                drop(reservation);
            }
            .instrument(span),
        );
    }
}

/// `killOp` every operation [`find_opids_by_marker`] finds.
async fn kill_ops_by_marker(client: &Client, marker: &str) {
    let admin = client.database("admin");
    for opid in find_opids_by_marker(&admin, marker).await {
        if let Err(err) = admin.run_command(doc! { "killOp": 1, "op": opid }).await {
            // `killOp` commonly fails with "unauthorized" when the role lacks
            // the privilege documented in the module docs — that is an
            // expected, not exceptional, outcome for operators who haven't
            // opted in. Warn, don't error: `maxTimeMS` is still the backstop.
            // Log only the driver's error category — never `%err`, whose
            // `Display` can surface `Authentication` / `ServerSelection`
            // messages carrying credentials or hostnames (CLAUDE.md
            // `src/exec/**` redaction rule).
            tracing::warn!(
                error_kind = classify_mongo_error(&err),
                "killOp failed during mongo cancel (missing privilege, or op already finished)"
            );
        }
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
#[path = "cancel_tests.rs"]
mod tests;
