//! Regression guard for CLAUDE.md §Testing: every integration test that
//! sends a `tools/call` asserts an audit row through `common::audit` —
//! `assert_audit_outcome`, or `latest_audit` when the test inspects more of
//! the row (both fail the test when the row is missing). Grep-level and per
//! file — cheap, and it catches a new tool test that forgets the audit half.
//!
//! A file whose `tools/call` requests never reach dispatch (wire-protocol
//! rejections with no caller identity to audit) opts out with a line
//! `// audit-guard: exempt — <reason>`; the reason is mandatory.

use std::fs;
use std::path::{Path, PathBuf};

const TOOL_CALL: &str = "\"tools/call\"";
const ASSERTIONS: &[&str] = &["assert_audit_outcome(", "latest_audit("];
const EXEMPT_MARKER: &str = "// audit-guard: exempt — ";

fn test_sources() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("tests/ is readable")
        .map(|entry| entry.expect("tests/ entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();
    files
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("UTF-8 file name")
}

fn is_exempt(source: &str) -> bool {
    source.lines().any(|line| {
        line.trim_start()
            .strip_prefix(EXEMPT_MARKER)
            .is_some_and(|reason| !reason.trim().is_empty())
    })
}

#[test]
fn every_tools_call_test_asserts_an_audit_row() {
    let this_file = file_name(Path::new(file!()));
    let offenders: Vec<String> = test_sources()
        .iter()
        .filter(|path| file_name(path) != this_file)
        .filter_map(|path| {
            let source = fs::read_to_string(path).expect("test source is UTF-8");
            let asserted = ASSERTIONS.iter().any(|helper| source.contains(helper));
            let unasserted = source.contains(TOOL_CALL) && !asserted && !is_exempt(&source);
            unasserted.then(|| file_name(path).to_string())
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "these tests send `tools/call` but never assert an audit row via \
         {ASSERTIONS:?} (CLAUDE.md §Testing): {offenders:?}"
    );
}

#[test]
fn exemption_requires_a_reason() {
    assert!(is_exempt(
        "// audit-guard: exempt — no identity, never dispatched"
    ));
    assert!(!is_exempt("// audit-guard: exempt — "));
    assert!(!is_exempt("no marker here"));
}
