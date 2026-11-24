//! Regression guard for CLAUDE.md §Testing: every integration test that
//! sends a `tools/call` asserts an audit row through `common::audit` —
//! `assert_audit_outcome`, or `latest_audit` when the test inspects more of
//! the row (both fail the test when the row is missing).
//!
//! Per test function, not per file: a file where one test asserts its row no
//! longer covers a sibling that forgot to. A test "sends" when its body, or a
//! helper it calls (transitively, by name: the file's own fn first, else a
//! shared harness — `tests/common/` or a module with no tests of its own,
//! such as `boot_binary.rs`), holds the `"tools/call"` literal; it "asserts" the same
//! way through the assertion helpers. Grep-level and name-based — cheap, and
//! it catches a new tool test that forgets the audit half.
//!
//! A test whose `tools/call` requests never reach dispatch (wire-protocol
//! rejections with no caller identity to audit) opts out with a line
//! `// audit-guard: exempt — <reason>` in its attribute block, or once at the
//! top of a file for every test in it; the reason is mandatory.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const TOOL_CALL: &str = "\"tools/call\"";
const ASSERTIONS: &[&str] = &[
    "assert_audit_outcome(",
    "latest_audit(",
    "calls_for_request(",
];
const EXEMPT_MARKER: &str = "// audit-guard: exempt — ";

/// One `fn` item: where it lives, whether it is a test, and its body text.
#[derive(Debug)]
struct Item {
    file: String,
    name: String,
    test: bool,
    exempt: bool,
    body: String,
    /// `body` minus comments and literals: where calls are looked for, so a
    /// `"redis.call(…)"` string is not a call to a harness `call`.
    code: String,
}

/// Every source under `tests/`, including the modules of the grouped binaries
/// (`tests/<group>/*.rs`) and the `tests/common/` harness (its helpers can
/// send or assert on a test's behalf).
fn test_sources() -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut files,
    );
    files.sort();
    files
}

fn collect_sources(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("tests/ dir is readable") {
        let path = entry.expect("tests/ entry").path();
        if path.is_dir() {
            collect_sources(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn is_exempt_line(line: &str) -> bool {
    line.trim_start()
        .strip_prefix(EXEMPT_MARKER)
        .is_some_and(|reason| !reason.trim().is_empty())
}

fn is_exempt(source: &str) -> bool {
    source.lines().any(is_exempt_line)
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The body of the item whose signature starts at `from`: the text between
/// its first `{` and the matching `}`, or `None` for a bodiless declaration.
fn body_from(source: &str, from: usize) -> Option<&str> {
    let rest = &source[from..];
    let open = rest.find(['{', ';'])?;
    if rest.as_bytes()[open] == b';' {
        return None;
    }
    let bytes = rest.as_bytes();
    let (mut depth, mut i) = (0usize, open);
    while i < bytes.len() {
        i = skip_literal(rest, i);
        match bytes.get(i) {
            Some(b'{') => depth += 1,
            Some(b'}') => {
                depth -= 1;
                if depth == 0 {
                    return Some(&rest[open + 1..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Past any comment, string or char literal starting at `i` (so a `"{"` or
/// a `// }` cannot unbalance the brace count); `i` itself otherwise.
fn skip_literal(text: &str, i: usize) -> usize {
    let Some(tail) = text.get(i..) else {
        return i;
    };
    let after = |close: &str, open_len: usize| {
        tail[open_len..]
            .find(close)
            .map_or(text.len(), |at| i + open_len + at + close.len())
    };
    if tail.starts_with("//") {
        return after("\n", 2);
    }
    if tail.starts_with("r#\"") {
        return after("\"#", 3);
    }
    if tail.starts_with("r\"") {
        return after("\"", 2);
    }
    if tail.starts_with('"') {
        let mut escaped = false;
        for (at, c) in tail.char_indices().skip(1) {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => return i + at + 1,
                _ => {}
            }
        }
        return text.len();
    }
    // A char literal ('x', '\''), not a lifetime ('a): the closing quote
    // follows one (possibly escaped) char.
    let mut chars = tail.char_indices();
    if let (Some((_, '\'')), Some((_, first))) = (chars.next(), chars.next()) {
        if first == '\\' {
            chars.next();
        }
        if let Some((at, '\'')) = chars.next() {
            return i + at + 1;
        }
    }
    i
}

fn code_only(body: &str) -> String {
    let mut code = String::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let next = skip_literal(body, i);
        if next > i {
            code.push(' ');
            i = next;
        } else if let Some(c) = body[i..].chars().next() {
            code.push(c);
            i += c.len_utf8();
        }
    }
    code
}

/// The lines above the first `fn` item's attribute block: where a file-wide
/// exemption lives. A marker in that block exempts only that item.
fn file_header(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let first_fn = lines
        .iter()
        .position(|l| !l.trim_start().starts_with("//") && l.contains("fn "))
        .unwrap_or(lines.len());
    let attrs = lines[..first_fn]
        .iter()
        .rev()
        .map(|l| l.trim())
        .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
        .count();
    lines[..first_fn - attrs].join("\n")
}

/// Every `fn` in `source` with its attribute block's test/exempt flags.
fn items(file: &str, source: &str) -> Vec<Item> {
    let lines: Vec<&str> = source.lines().collect();
    let mut offset = 0;
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let start = offset;
        offset += line.len() + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(at) = trimmed
            .find("fn ")
            .filter(|&at| at == 0 || !is_ident(trimmed[..at].chars().next_back().unwrap_or(' ')))
        else {
            continue;
        };
        let name: String = trimmed[at + 3..]
            .chars()
            .take_while(|&c| is_ident(c))
            .collect();
        let Some(body) = body_from(source, start + (line.len() - trimmed.len()) + at) else {
            continue;
        };
        let attrs: Vec<&str> = lines[..index]
            .iter()
            .rev()
            .map(|l| l.trim())
            .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
            .collect();
        found.push(Item {
            file: file.to_string(),
            name,
            test: attrs
                .iter()
                .any(|l| *l == "#[test]" || l.starts_with("#[tokio::test")),
            exempt: attrs.iter().any(|l| is_exempt_line(l)),
            body: body.to_string(),
            code: code_only(body),
        });
    }
    found
}

/// Whether `body` calls `name` — `name(` or `.name(` after a non-ident char.
fn calls(body: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    body.match_indices(&needle)
        .any(|(at, _)| body[..at].chars().next_back().is_none_or(|c| !is_ident(c)))
}

/// Fixpoint of "holds one of `literals`, or calls an item that does": the
/// indices of every item with the property. A call resolves to the caller's
/// own file first, else to every item of that name in a shared harness.
fn closure(items: &[Item], harness: &BTreeSet<String>, literals: &[&str]) -> BTreeSet<usize> {
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, item) in items.iter().enumerate() {
        by_name.entry(&item.name).or_default().push(i);
    }
    let mut set: BTreeSet<usize> = (0..items.len())
        .filter(|&i| literals.iter().any(|lit| items[i].body.contains(lit)))
        .collect();
    loop {
        let before = set.len();
        for (i, item) in items.iter().enumerate() {
            if set.contains(&i) {
                continue;
            }
            let reaches = by_name.iter().any(|(name, targets)| {
                let local: Vec<usize> = targets
                    .iter()
                    .copied()
                    .filter(|&t| items[t].file == item.file)
                    .collect();
                let shared: Vec<usize> = targets
                    .iter()
                    .copied()
                    .filter(|&t| harness.contains(&items[t].file))
                    .collect();
                let scope = if local.is_empty() { &shared } else { &local };
                scope.iter().any(|t| set.contains(t)) && calls(&item.code, name)
            });
            if reaches {
                set.insert(i);
            }
        }
        if set.len() == before {
            return set;
        }
    }
}

/// `file::fn` of every test that sends a `tools/call` and asserts no row.
fn unasserted(items: &[Item], exempt_files: &BTreeSet<String>) -> Vec<String> {
    let has_tests: BTreeSet<&String> = items
        .iter()
        .filter(|item| item.test)
        .map(|item| &item.file)
        .collect();
    let harness: BTreeSet<String> = items
        .iter()
        .map(|item| item.file.clone())
        .filter(|file| file.starts_with("tests/common/") || !has_tests.contains(file))
        .collect();
    let sends = closure(items, &harness, &[TOOL_CALL]);
    let asserts = closure(items, &harness, ASSERTIONS);
    items
        .iter()
        .enumerate()
        .filter(|(i, item)| item.test && sends.contains(i) && !asserts.contains(i))
        .filter(|(_, item)| !item.exempt && !exempt_files.contains(&item.file))
        .map(|(_, item)| format!("{}::{}", item.file, item.name))
        .collect()
}

#[test]
fn every_tools_call_test_asserts_an_audit_row() {
    let this_file = Path::new(file!()).file_name().expect("file name");
    let mut all = Vec::new();
    let mut exempt_files = BTreeSet::new();
    for path in test_sources() {
        if path.file_name() == Some(this_file) {
            continue;
        }
        let file = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .expect("under the manifest dir")
            .display()
            .to_string();
        let source = fs::read_to_string(&path).expect("test source is UTF-8");
        if is_exempt(&file_header(&source)) {
            exempt_files.insert(file.clone());
        }
        all.extend(items(&file, &source));
    }
    assert!(all.iter().any(|item| item.test), "scanned no tests");
    let offenders = unasserted(&all, &exempt_files);
    assert!(
        offenders.is_empty(),
        "these tests send `tools/call` but never assert an audit row via \
         {ASSERTIONS:?} (CLAUDE.md §Testing): {offenders:?}"
    );
}

#[test]
fn an_exempt_first_test_does_not_exempt_its_siblings() {
    let source = r##"//! A test module.
use std::fs;

#[tokio::test]
// audit-guard: exempt — refused before dispatch
async fn excused() { post("tools/call").await; }
#[tokio::test]
async fn forgot() { post("tools/call").await; }
"##;
    assert!(!is_exempt(&file_header(source)), "{}", file_header(source));
    let file_wide = format!("// audit-guard: exempt — no identity\n{source}");
    assert!(is_exempt(&file_header(&file_wide)));
    let found = items("x.rs", source);
    assert_eq!(unasserted(&found, &BTreeSet::new()), vec!["x.rs::forgot"]);
}

#[test]
fn exemption_requires_a_reason() {
    assert!(is_exempt(
        "// audit-guard: exempt — no identity, never dispatched"
    ));
    assert!(!is_exempt("// audit-guard: exempt — "));
    assert!(!is_exempt("no marker here"));
}

#[test]
fn a_sibling_test_does_not_cover_one_that_forgot() {
    let source = r##"
async fn send() { post("tools/call").await; }
#[tokio::test]
async fn covered() { send().await; latest_audit(&pool, "u", "t", "l").await; }
#[tokio::test]
async fn forgot() { send().await; }
#[tokio::test]
// audit-guard: exempt — refused before dispatch
async fn excused() { send().await; }
#[tokio::test]
async fn unrelated() { let s = "{ send() }"; let c = '}'; let r = r#"{"#; } // }
"##;
    let found = items("x.rs", source);
    assert_eq!(found.len(), 5, "{found:?}");
    assert_eq!(unasserted(&found, &BTreeSet::new()), vec!["x.rs::forgot"]);
    let exempt = BTreeSet::from(["x.rs".to_string()]);
    assert!(unasserted(&found, &exempt).is_empty());
}
