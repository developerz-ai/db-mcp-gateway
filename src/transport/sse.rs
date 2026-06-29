//! Server→client SSE stream for the Streamable HTTP transport.
//!
//! On connect we emit a non-normative `greeting` event carrying the protocol
//! version and server identity, so a plain `curl` confirms the gateway is up and
//! speaking MCP. The stream then stays open with keep-alive comments, ready for
//! server-initiated messages once later layers produce them.

use std::convert::Infallible;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::stream::{self, Stream, StreamExt};
use tokio::sync::{Semaphore, SemaphorePermit};

use super::protocol::InitializeResult;

/// Cap on concurrent server→client SSE streams.
///
/// `GET /mcp` is on the open (unauthenticated) router and its stream never ends
/// — it only carries server-initiated messages — so every connection pins a
/// socket + task + keep-alive timer until the client disconnects. Without a
/// bound, an unauthenticated client could open streams until the process runs
/// out of file descriptors / task memory (sec qa 2026-06-29 T2). 256 is ample
/// for legitimate agents (roughly one stream per active MCP session) while
/// keeping an abusive client's blast radius finite; the permit is released the
/// moment the connection drops.
const MAX_SSE_CONNECTIONS: usize = 256;

/// Module-level so the cap is process-wide without threading new state through
/// `AppState`. `const_new` lets it live in a `static` with no init dance.
static SSE_CONNECTIONS: Semaphore = Semaphore::const_new(MAX_SSE_CONNECTIONS);

pub async fn handler() -> Response {
    // Reject when the cap is full instead of unboundedly accepting connections.
    // The permit is moved into the stream below so the slot is held for the
    // connection lifetime and released on disconnect (stream drop).
    let permit = match SSE_CONNECTIONS.try_acquire() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let greeting = match Event::default()
        .event("greeting")
        .json_data(InitializeResult::new())
    {
        Ok(event) => event,
        Err(_) => Event::default().comment("greeting serialization failed"),
    };

    let stream = greeting_stream(greeting, permit);

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// Greeting once, then park forever — owning `permit` in the stream's state so
/// the connection counts against the cap until the client disconnects (which
/// drops the stream and the parked future, releasing the slot).
fn greeting_stream(
    greeting: Event,
    permit: SemaphorePermit<'static>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::once(async move { Ok::<Event, Infallible>(greeting) }).chain(stream::unfold(
        permit,
        |permit| async move {
            // Move `permit` into this never-resolving future so it's owned for
            // the connection's life (dropped, releasing the slot, on disconnect).
            let _permit = permit;
            std::future::pending::<Option<(Result<Event, Infallible>, SemaphorePermit<'static>)>>()
                .await
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_connection_cap_rejects_when_full() {
        // Drain every slot, then the next acquire must fail (handler → 503).
        let permits: Vec<_> = (0..MAX_SSE_CONNECTIONS)
            .map(|_| {
                SSE_CONNECTIONS
                    .try_acquire()
                    .expect("permit available under cap")
            })
            .collect();
        assert!(
            SSE_CONNECTIONS.try_acquire().is_err(),
            "acquire past MAX_SSE_CONNECTIONS must fail"
        );
        // Release so the static is clean for any later use in this binary.
        drop(permits);
    }
}
