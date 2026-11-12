//! Pure-logic tests — full real-DB coverage lives in
//! `tests/get_query_history_real_db.rs`.

use super::*;

/// The ceiling clamp is the only thing that stands between a caller
/// asking for `u32::MAX` rows and the audit table serving up a giant
/// slice. Pin both branches of the clamp here.
#[test]
fn effective_limit_clamps_to_ceiling() {
    assert_eq!(effective_limit(Some(u32::MAX)), GATEWAY_ROW_LIMIT_CEILING);
    assert_eq!(
        effective_limit(Some(4_000_000_000)),
        GATEWAY_ROW_LIMIT_CEILING
    );
}

#[test]
fn effective_limit_passes_through_small_values() {
    assert_eq!(effective_limit(Some(50)), 50);
    assert_eq!(effective_limit(Some(1)), 1);
}

#[test]
fn effective_limit_uses_default_when_absent() {
    assert_eq!(effective_limit(None), DEFAULT_HISTORY_LIMIT);
}

/// `truncated` means "your limit was clamped", never "there is more
/// data". An agent that reads it the second way retries with a bigger
/// `limit` against a ceiling that cannot yield more, instead of widening
/// `since`. Pin every branch of that distinction.
#[test]
fn truncated_reports_the_ceiling_clamp_only() {
    let ceiling = GATEWAY_ROW_LIMIT_CEILING;

    // Above the ceiling: clamped, so flagged.
    assert!(limit_was_clamped(
        Some(u32::MAX),
        effective_limit(Some(u32::MAX))
    ));

    // Exactly at the ceiling: honoured verbatim, nothing clamped.
    assert!(!limit_was_clamped(
        Some(ceiling),
        effective_limit(Some(ceiling))
    ));

    // A small limit is honoured — even when more entries exist, which
    // this flag deliberately says nothing about.
    assert!(!limit_was_clamped(Some(10), effective_limit(Some(10))));

    // No caller limit: the default applies and nothing was asked for
    // that could be clamped.
    assert!(!limit_was_clamped(None, effective_limit(None)));
}

/// `since` parsing is the edge that decides whether a malformed value
/// silently drops the filter (= window widening = data exposure) or
/// rejects the call. Pin both directions.
#[test]
fn parse_since_accepts_rfc3339_utc() {
    let ts = parse_since(Some("2026-08-05T00:00:00Z")).expect("parses");
    assert_eq!(
        ts.expect("Some"),
        DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    );
}

#[test]
fn parse_since_accepts_rfc3339_with_offset() {
    let ts = parse_since(Some("2026-08-05T08:00:00+08:00")).expect("parses");
    assert_eq!(
        ts.expect("Some"),
        DateTime::parse_from_rfc3339("2026-08-05T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    );
}

#[test]
fn parse_since_rejects_garbage() {
    assert!(parse_since(Some("yesterday")).is_err());
    assert!(parse_since(Some("")).is_err());
    assert!(parse_since(Some("2026-13-40")).is_err());
}

#[test]
fn parse_since_none_is_none() {
    assert!(parse_since(None).unwrap().is_none());
}

/// THE SECURITY TEST. `deny_unknown_fields` is the type-level promise
/// that no caller-supplied `user` (or any other identity override) can
/// slip into the deserialized arguments. A regression that drops the
/// attribute would compile cleanly but silently allow the bypass —
/// pin it here.
#[test]
fn arguments_rejects_user_field_at_deserialize() {
    let json = serde_json::json!({
        "server": "prod",
        "database": "app",
        "user": "someone-else", // <- smuggling attempt
    });
    let result: Result<Arguments, _> = serde_json::from_value(json);
    assert!(
        result.is_err(),
        "Arguments must reject unknown `user` field — got {result:?}",
    );
}

#[test]
fn arguments_accepts_canonical_shape() {
    let json = serde_json::json!({
        "server": "prod",
        "database": "app",
    });
    let args: Arguments = serde_json::from_value(json).expect("canonical parses");
    assert_eq!(args.server, "prod");
    assert_eq!(args.database, "app");
    assert!(args.since.is_none());
    assert!(args.limit.is_none());
}

#[test]
fn arguments_accepts_optional_fields() {
    let json = serde_json::json!({
        "server": "prod",
        "database": "app",
        "since": "2026-08-05T00:00:00Z",
        "limit": 25,
    });
    let args: Arguments = serde_json::from_value(json).expect("full parses");
    assert_eq!(args.since.as_deref(), Some("2026-08-05T00:00:00Z"));
    assert_eq!(args.limit, Some(25));
}
