//! Regression guard for `tests/it_db/`: every module shares one process under
//! plain `cargo test`, so every test there must declare its isolation on the
//! `world` key — `#[serial_test::serial(world)]` for a test with a table-wide
//! or global side effect, `#[serial_test::parallel(world)]` otherwise (see
//! `tests/it_db/main.rs`). A test with neither would run beside a global
//! sweep and flake.

use std::fs;
use std::path::Path;

const ISOLATION: &[&str] = &[
    "#[serial_test::serial(world)]",
    "#[serial_test::parallel(world)]",
];

fn is_test_attr(line: &str) -> bool {
    line == "#[test]" || line.starts_with("#[tokio::test")
}

/// `file:line` of every test attribute in `source` whose attribute block
/// carries no `world` isolation attribute.
fn undeclared(file: &str, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let mut offenders = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !is_test_attr(line) {
            continue;
        }
        let start = lines[..index]
            .iter()
            .rposition(|l| !l.starts_with("#[") && !l.starts_with("//"))
            .map_or(0, |i| i + 1);
        let end = lines[index..]
            .iter()
            .position(|l| !l.starts_with("#[") && !l.starts_with("//"))
            .map_or(lines.len(), |i| index + i);
        let declared = lines[start..end].iter().any(|l| ISOLATION.contains(l));
        if !declared {
            offenders.push(format!("{file}:{}", index + 1));
        }
    }
    offenders
}

#[test]
fn every_it_db_test_declares_its_world_isolation() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it_db");
    let mut offenders = Vec::new();
    let mut tests_seen = 0;
    for entry in fs::read_dir(&dir).expect("tests/it_db is readable") {
        let path = entry.expect("tests/it_db entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("test source is UTF-8");
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("UTF-8 name");
        tests_seen += source.lines().filter(|l| is_test_attr(l.trim())).count();
        offenders.extend(undeclared(name, &source));
    }
    assert!(tests_seen > 0, "scanned no tests in {}", dir.display());
    assert!(
        offenders.is_empty(),
        "these it_db tests declare neither {ISOLATION:?}: {offenders:?}"
    );
}

#[test]
fn guard_fires_on_a_test_without_isolation() {
    let bare = "#[tokio::test]\nasync fn t() {}\n";
    assert_eq!(undeclared("x.rs", bare), vec!["x.rs:1"]);
    let declared = "#[tokio::test]\n#[serial_test::parallel(world)]\nasync fn t() {}\n";
    assert!(undeclared("x.rs", declared).is_empty());
    let before = "#[serial_test::serial(world)]\n#[test]\nfn t() {}\n";
    assert!(undeclared("x.rs", before).is_empty());
}
