//! Server→client SSE stream for the Streamable HTTP transport.
//!
//! On connect we emit a non-normative `greeting` event carrying the protocol
//! version and server identity, so a plain `curl` confirms the gateway is up and
//! speaking MCP. The stream then stays open with keep-alive comments, ready for
//! server-initiated messages once later layers produce them.

use std::convert::Infallible;
use std::time::Duration;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::{self, Stream, StreamExt};

use super::protocol::InitializeResult;

pub async fn handler() -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let greeting = match Event::default()
        .event("greeting")
        .json_data(InitializeResult::new())
    {
        Ok(event) => event,
        Err(_) => Event::default().comment("greeting serialization failed"),
    };

    let stream = stream::once(async move { Ok::<Event, Infallible>(greeting) })
        .chain(stream::pending::<Result<Event, Infallible>>());

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
