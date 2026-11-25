//! `redact_role` over arbitrary server text. Redis names the ACL user
//! unquoted, next to text the agent controls (key names, command args), so
//! the contract is in words: every whole-word occurrence of the role is
//! replaced, and text that holds none comes back byte-identical.

use proptest::prelude::*;

use super::{ROLE_PLACEHOLDER, redact_role};

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whole-word occurrences of `role` in `text`.
fn whole_words(text: &str, role: &str) -> usize {
    text.split(|c: char| !is_word(c))
        .filter(|word| *word == role)
        .count()
}

/// An ACL user name the config accepts (`validate_role`).
fn role() -> impl Strategy<Value = String> {
    "[A-Za-z_][A-Za-z0-9_]{0,11}"
}

/// A server message: the role and filler in any order, glued by nothing,
/// quotes, punctuation or spaces — so the role turns up as a whole word,
/// inside a longer word, and next to copies of itself.
fn message(role: String) -> impl Strategy<Value = (String, String)> {
    let piece = prop_oneof![
        Just(role.clone()),
        Just(role.to_uppercase()),
        "[A-Za-z0-9_]{0,6}",
        "\\PC{0,6}",
    ];
    let glue = prop_oneof![Just(String::new()), "[ '\"`:.,()=/<>-]{1,2}"];
    prop::collection::vec((piece, glue), 0..8).prop_map(move |parts| {
        let text = parts.into_iter().map(|(p, g)| p + &g).collect();
        (role.clone(), text)
    })
}

proptest! {
    #[test]
    fn no_whole_word_role_survives(
        (role, text) in role().prop_flat_map(message),
    ) {
        let out = redact_role(&text, &role);
        // A role spelled like the placeholder's own word (`role`) is not a leak.
        let without_placeholders = out.replace(ROLE_PLACEHOLDER, " ");
        prop_assert_eq!(whole_words(&without_placeholders, &role), 0, "{:?} -> {:?}", text, out);
    }

    #[test]
    fn text_without_the_role_as_a_word_is_unchanged(
        (role, text) in role().prop_flat_map(message),
    ) {
        prop_assume!(whole_words(&text, &role) == 0);
        prop_assert_eq!(redact_role(&text, &role), text);
    }

    /// Non-triviality: a role between separators is actually replaced, so the
    /// properties above are not passing on a function that does nothing.
    #[test]
    fn a_planted_role_is_replaced(
        role in role(),
        before in "\\PC{0,12}",
        after in "\\PC{0,12}",
        quote in prop::sample::select(vec!["", "'", "\"", "`"]),
    ) {
        let text = format!("{before} {quote}{role}{quote} {after}");
        let out = redact_role(&text, &role);
        prop_assert!(out.contains(ROLE_PLACEHOLDER), "{text:?} -> {out:?}");
        prop_assert_ne!(out, text);
    }
}
