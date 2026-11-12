//! Per-field coverage of `scrub_event`: breadcrumbs, tags, user, request.

use super::scrubber;

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
