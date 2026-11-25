//! A credential planted anywhere in an event never reaches GlitchTip: a DSN
//! password, a bearer value, a `dbmcp_svc_` token or a conninfo `password=`,
//! amid arbitrary text, in any field the scrubber walks.

use proptest::prelude::*;
use sentry::protocol::{Breadcrumb, Event, Exception};

use super::scrubber::{REDACTED, Scrubber};

/// A field nobody plants into: it must come back untouched, so the scrubber
/// is not passing by flattening the whole event.
const CULPRIT: &str = "gateway::exec::pool";

/// Long enough that the surrounding text cannot spell it by chance.
fn secret() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{16,24}"
}

/// The secret wrapped in one of the shapes it travels in.
fn credential(secret: String) -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        "(postgres|postgresql|mysql|mongodb|redis)://[a-z_]{1,8}"
            .prop_map(|prefix| format!("{prefix}:{{}}@db.internal:5432/app")),
        "[Bb][Ee][Aa][Rr][Ee][Rr]".prop_map(|scheme| format!("{scheme} {{}}")),
        Just("dbmcp_svc_{}".to_owned()),
        "[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]"
            .prop_map(|key| format!("host=db.internal user=app {key}={{}} dbname=app")),
    ]
    .prop_map(move |shape| (secret.clone(), shape.replace("{}", &secret)))
}

fn planted_event(field: usize, text: String) -> Event<'static> {
    let mut event = Event {
        culprit: Some(CULPRIT.to_owned()),
        ..Event::default()
    };
    match field {
        0 => event.message = Some(text),
        1 => event.exception.values.push(Exception {
            ty: "Error".to_owned(),
            value: Some(text),
            ..Exception::default()
        }),
        2 => event.breadcrumbs.values.push(Breadcrumb {
            message: Some(text),
            ..Breadcrumb::default()
        }),
        3 => {
            event
                .extra
                .insert("ctx".to_owned(), serde_json::json!({ "detail": [text] }));
        }
        _ => {
            event.tags.insert("note".to_owned(), text);
        }
    }
    event
}

proptest! {
    #[test]
    fn a_planted_credential_never_survives_scrubbing(
        (secret, credential) in secret().prop_flat_map(credential),
        before in "\\PC{0,24}",
        after in "\\PC{0,24}",
        field in 0..5usize,
    ) {
        let event = planted_event(field, format!("{before} {credential} {after}"));
        // Non-triviality: the secret really is in the event before scrubbing.
        let raw = serde_json::to_string(&event).expect("event serialises");
        prop_assert!(raw.contains(&secret));

        let scrubber = Scrubber::new().expect("scrubber patterns compile");
        let scrubbed = scrubber.scrub_event(event).expect("event round-trips");
        let shipped = serde_json::to_string(&scrubbed).expect("event serialises");
        prop_assert!(!shipped.contains(&secret), "leaked: {shipped}");
        prop_assert!(shipped.contains(REDACTED), "nothing redacted: {shipped}");
        prop_assert_eq!(scrubbed.culprit.as_deref(), Some(CULPRIT));
    }
}
