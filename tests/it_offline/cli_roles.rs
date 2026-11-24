//! `roles`: the print-only provisioning SQL, pinned as a snapshot.

use crate::cli_check::gateway;

#[test]
fn roles_output_matches_the_snapshot() {
    let output = gateway(
        &[
            "roles",
            "--config",
            "tests/data/check/good.yaml",
            "--owner",
            "app_owner",
            "--schema",
            "public",
            "--schema",
            "sales",
        ],
        &[],
    );
    assert_eq!(output.status.code(), Some(0));
    let out = String::from_utf8(output.stdout).unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/check/roles.out");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, &out).unwrap();
    }
    assert_eq!(out, std::fs::read_to_string(path).unwrap());
    // Print-only: nothing in it is resolved from a secret reference.
    assert!(!out.contains("CHECK_APP_RO_PASSWORD"));
}

#[test]
fn an_unmatched_filter_fails() {
    let output = gateway(
        &[
            "roles",
            "--config",
            "tests/data/check/good.yaml",
            "--server",
            "nope",
        ],
        &[],
    );
    assert_eq!(output.status.code(), Some(1));
}
