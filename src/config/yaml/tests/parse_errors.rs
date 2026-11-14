//! Parse failures: operators get position and schema hints, never config bytes.

use crate::config::yaml::{ConfigFile, ConfigFileError};

/// The headline example from #16: a typo in a `Constraints` field used to
/// be silently ignored (no timeout applied). Now it surfaces with the
/// misspelled key, the expected alternatives, and a line number.
#[test]
fn typo_in_constraint_field_is_rejected_with_line_and_suggestion() {
    let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - { name: app, role: ro, password: x }
permissions:
  - group: g
    grants:
      - server: prod
        database: app
        action: query_read
        constraints:
          statemnt_timeout_ms: 5000
";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("typo must be rejected");
    let rendered = format!("{err}");
    // Display points at the line but must NOT echo the raw serde text
    // (which can carry an offending scalar). The misspelled key and the
    // suggestion list live in the `source` chain only.
    assert!(
        !rendered.contains("statemnt_timeout_ms"),
        "Display must not echo raw serde text: {rendered}"
    );
    // The parser reports the line of the offending key. Exact column varies
    // by parser version; assert just on a `:line:column` shape.
    assert!(
        rendered.contains(":14:") || rendered.contains(":13:"),
        "expected `:14:` or `:13:` line marker in: {rendered}"
    );
    // The schema's own field list is safe to show, and is the half that
    // actually helps — it names the key the operator meant.
    assert!(
        rendered.contains("statement_timeout_ms"),
        "operator lost the suggestion list: {rendered}"
    );
}

/// A typo in a key on the next-most-likely error surface — a `Database`
/// field — fails the same way. Defends the per-struct `deny_unknown_fields`
/// coverage across the inner schema, not just `Constraints`.
#[test]
fn typo_in_database_field_is_rejected() {
    let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    databases:
      - name: app
        role: ro
        password: x
        descriptoin: typo here
";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("typo must be rejected");
    let rendered = format!("{err}");
    // Same contract: the operator's own text never comes back, the schema's
    // does.
    assert!(
        !rendered.contains("descriptoin"),
        "echoed the operator's typo back: {rendered}"
    );
    assert!(
        rendered.contains("description"),
        "missing suggestion: {rendered}"
    );
}

/// A misspelled enum variant (action name) yields the same kind of
/// expected-vs-got message serde gives for unknown variants — surfaces
/// before the runtime can reach a confused authz miss.
#[test]
fn misspelled_action_is_rejected_with_variant_list() {
    let yaml = "\
servers:
  - { name: prod, kind: postgres, host: a, databases: [{ name: app, role: ro, password: x }] }
permissions:
  - group: g
    grants:
      - { server: prod, database: app, action: query_reed }
";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("typo must be rejected");
    let rendered = format!("{err}");
    // An enum-typed field is the one place a mis-pasted secret would be
    // echoed as the "got" token, so the got half is dropped entirely.
    assert!(
        !rendered.contains("query_reed"),
        "echoed the operator's token back: {rendered}"
    );
    assert!(
        rendered.contains("query_read"),
        "operator lost the variant list: {rendered}"
    );
}

/// A mis-pasted value that itself contains the `expected one of ` marker
/// must not ride the schema list out: neither as an enum token (marker
/// before the real list) nor as a scalar in a non-enum field (no real list).
#[test]
fn value_containing_the_marker_never_leaks() {
    let enum_token = "\
servers:
  - { name: prod, kind: postgres, host: a, databases: [{ name: app, role: ro, password: x }] }
permissions:
  - group: g
    grants:
      - { server: prod, database: app, action: \"x expected one of hunter2\" }
";
    let typed_scalar = "\
servers:
  - { name: prod, kind: postgres, host: a, port: \"expected one of hunter2\" }
";
    for yaml in [enum_token, typed_scalar] {
        let err = ConfigFile::from_yaml_str(yaml).expect_err("bad value must reject");
        let chain = error_chain(&err);
        assert!(!chain.contains("hunter2"), "leaked the value: {chain}");
    }
}

/// C4: a parse error must never carry the offending scalar — it may be a
/// password mis-pasted into a typed field.
///
/// Tightened by the `serde_yaml` → `serde-saphyr` swap. This used to assert
/// only that `Display` suppressed the value while `source` was allowed to
/// keep it — a distinction that turned out not to exist, because `main`
/// returns `anyhow::Result` and `anyhow` prints the whole `Caused by:`
/// chain. The variant now carries no parser text at all, so the value is
/// absent from every layer, which is what this pins.
#[test]
fn parse_error_display_omits_raw_serde_text() {
    // `port` wants u16; the string value is the kind of scalar serde would
    // otherwise echo verbatim into its message.
    let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    port: \"sup3r-s3cret-looking-scalar\"
";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("type mismatch must be rejected");
    let rendered = format!("{err}");
    assert!(
        !rendered.contains("sup3r-s3cret-looking-scalar"),
        "Display leaked the offending scalar: {rendered}"
    );
    assert!(
        rendered.contains("invalid configuration"),
        "Display should be the generic operator line: {rendered}"
    );
    let ConfigFileError::Parse { location, .. } = &err else {
        panic!("expected Parse, got {err:?}");
    };

    // The chain is what actually reaches a terminal on boot. Walk the whole
    // of it the way `anyhow` does, rather than trusting `Display` alone.
    assert!(
        !error_chain(&err).contains("sup3r-s3cret-looking-scalar"),
        "error chain leaked the offending scalar: {}",
        error_chain(&err)
    );

    // Suppressing the value is only acceptable because the position
    // survives — that is what an operator actually navigates by.
    assert_eq!(location, ":5:11", "operators lost the offending position");
}

/// Render an error the way `anyhow` does when `main` returns `Err`: the
/// `Display` of every link in the `source` chain, concatenated.
///
/// The leak this guards against was invisible to a `format!("{err}")`
/// assertion — it lived one `source()` hop away and still printed to the
/// terminal. Tests that care about disclosure must look here, not at
/// `Display`.
fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut cursor = err.source();
    while let Some(link) = cursor {
        out.push_str(" | ");
        out.push_str(&link.to_string());
        cursor = link.source();
    }
    out
}

/// C4, second half — added with the `serde_yaml` → `serde-saphyr` swap,
/// and the reason [`non_leaking_options`] exists.
///
/// `serde-saphyr` defaults `with_snippet` to `true`, which attaches a
/// rustc-style window of the *surrounding* source to the error. On a config
/// file that is mostly credentials, that turns a type error on one line into
/// a disclosure of its neighbours: caught in review by this exact fixture,
/// which printed `password: "unrelated-neighbour-secret"` before the option
/// was turned off.
///
/// Strictly stronger than the test above — that one pins the *offending*
/// value, this one pins every *other* line in the file.
#[test]
fn parse_error_never_carries_secrets_from_neighbouring_lines() {
    // The secret sits in a real `Database.password` — a valid line the
    // parser accepts — so the only failure is `port`. An earlier draft put
    // `password:` directly on the server, where it is an *unknown field*;
    // that aborts on the unknown key and never reaches `port`, so the
    // fixture was testing a different code path than it claimed to.
    let yaml = "\
servers:
  - name: prod
    kind: postgres
    host: a
    port: \"not-a-number\"
    databases:
      - name: app
        role: ro
        password: \"unrelated-neighbour-secret\"
";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("type mismatch must be rejected");

    let chain = error_chain(&err);
    assert!(
        !chain.contains("unrelated-neighbour-secret"),
        "error chain pulled in a neighbouring line's secret: {chain}"
    );
    assert!(
        matches!(err, ConfigFileError::Parse { .. }),
        "expected Parse, got {err:?}"
    );
}

/// The leak that motivated severing the chain: `main` returns
/// `anyhow::Result`, and `anyhow` renders every `source()` link under
/// `Caused by:` when `main` returns `Err`. A parse error that keeps the
/// parser's text therefore reaches the terminal no matter how careful
/// `Display` is.
///
/// `Parse` has no `#[source]` for exactly this reason. Adding one back
/// re-opens the hole silently, so this asserts the chain has no second link
/// at all rather than checking for any particular secret.
#[test]
fn parse_error_has_no_source_chain_for_anyhow_to_render() {
    let yaml = "\
servers:
  - name: prod
    kind: \"hunter2-MISPASTED-PASSWORD\"
    host: a
";
    let err = ConfigFile::from_yaml_str(yaml).expect_err("bad variant must be rejected");

    assert!(
        std::error::Error::source(&err).is_none(),
        "Parse grew a source chain; anyhow will print it under `Caused by:`"
    );
    assert!(
        !error_chain(&err).contains("hunter2-MISPASTED-PASSWORD"),
        "the operator's token reached the rendered chain: {}",
        error_chain(&err)
    );
    // The schema half still helps them fix it.
    assert!(
        error_chain(&err).contains("postgres"),
        "operator lost the variant list: {}",
        error_chain(&err)
    );
}
