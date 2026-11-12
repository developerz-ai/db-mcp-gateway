//! Whole-event coverage: every protocol field, by value and by key, and the
//! JSON round-trip the scrubber relies on.

use super::scrubber;

/// Every event field plan 101 slice 11 step 2 names, each carrying a secret
/// either by value pattern or under a sensitive key. One serialised check
/// proves none survives; the event still round-trips.
#[test]
fn scrubs_every_protocol_field() {
    use sentry::protocol::{Event, Exception, Frame, LogEntry, Mechanism, Stacktrace};

    let secret = "hunter2";
    let dsn = format!("postgres://app:{secret}@db/app");
    let mut event = Event {
        logentry: Some(LogEntry {
            message: format!("connect {dsn}"),
            params: vec![serde_json::json!(format!("password={secret}"))],
        }),
        culprit: Some(format!("connect({dsn})")),
        transaction: Some(format!("token={secret}")),
        fingerprint: vec![format!("dsn={dsn}").into()].into(),
        ..Event::default()
    };
    let mut mechanism = Mechanism {
        ty: "generic".to_owned(),
        ..Mechanism::default()
    };
    mechanism
        .data
        .insert("api_key".to_owned(), serde_json::json!(secret));
    let mut frame = Frame::default();
    frame
        .vars
        .insert("password".to_owned(), serde_json::json!(secret));
    frame.vars.insert(
        "nested".to_owned(),
        serde_json::json!({ "Authorization": format!("Basic {secret}"), "n": 7 }),
    );
    event.exception.values.push(Exception {
        ty: "Error".to_owned(),
        value: Some("boom".to_owned()),
        module: Some(format!("mod {dsn}")),
        mechanism: Some(mechanism),
        stacktrace: Some(Stacktrace {
            frames: vec![frame],
            ..Stacktrace::default()
        }),
        ..Exception::default()
    });
    event
        .extra
        .insert("private_key".to_owned(), serde_json::json!([secret, 42]));

    let scrubbed = scrubber().scrub_event(event).expect("event round-trips");
    let json = serde_json::to_string(&scrubbed).expect("event serializes");
    assert!(!json.contains(secret), "secret survived: {json}");
    let ex = &scrubbed.exception.values[0];
    assert_eq!(ex.ty, "Error", "benign field rewritten");
    assert_eq!(ex.value.as_deref(), Some("boom"), "benign field rewritten");
}

/// A bare service token or bearer header under a non-sensitive key, and a
/// header whose *name* is sensitive, are both redacted.
#[test]
fn scrubs_service_token_and_bearer_header() {
    let token = format!("dbmcp_svc_{}", "ab".repeat(32));
    let mut request = sentry::protocol::Request::default();
    request
        .headers
        .insert("Authorization".to_owned(), "opaque-value".to_owned());
    request
        .headers
        .insert("X-Forwarded".to_owned(), format!("Bearer {token}"));
    let mut event = sentry::protocol::Event {
        message: Some(format!("rejected {token}")),
        request: Some(request),
        ..sentry::protocol::Event::default()
    };
    event
        .tags
        .insert("Set-Cookie".to_owned(), "sid=opaque-cookie".to_owned());

    let scrubbed = scrubber().scrub_event(event).expect("event round-trips");
    let json = serde_json::to_string(&scrubbed).expect("event serializes");
    for leak in [&token[10..], "opaque-value", "opaque-cookie"] {
        assert!(!json.contains(leak), "{leak} survived: {json}");
    }
}

/// The JSON round-trip must not drop a benign event (dropping fails closed,
/// but an error tracker that loses every event tells nobody anything): typed
/// fields — level, timestamp, contexts, request url, sdk — survive unchanged.
#[test]
fn benign_event_round_trips_unchanged() {
    use sentry::protocol::{Context, Event, Level, OsContext, Request, RuntimeContext};

    let mut event = Event {
        level: Level::Error,
        message: Some("pool exhausted for analytics/warehouse".to_owned()),
        platform: "native".into(),
        request: Some(Request {
            url: "https://gateway.example/mcp?x=1".parse().ok(),
            method: Some("POST".to_owned()),
            ..Request::default()
        }),
        ..Event::default()
    };
    event.contexts.insert(
        "os".to_owned(),
        Context::Os(Box::new(OsContext {
            name: Some("Linux".to_owned()),
            ..OsContext::default()
        })),
    );
    event.contexts.insert(
        "rust".to_owned(),
        Context::Runtime(Box::new(RuntimeContext {
            name: Some("rustc".to_owned()),
            ..RuntimeContext::default()
        })),
    );
    let before = serde_json::to_value(&event).expect("serializes");

    let scrubbed = scrubber().scrub_event(event).expect("round-trips");

    let after = serde_json::to_value(&scrubbed).expect("serializes");
    assert_eq!(before, after, "benign event rewritten by the scrubber");
}
