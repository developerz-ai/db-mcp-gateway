//! Regression guard for `tests/it_db/`: every module shares one process under
//! plain `cargo test`, so every test there must declare its isolation on the
//! `world` key — `#[serial_test::serial(world)]` for a test with a table-wide
//! or global side effect, `#[serial_test::parallel(world)]` otherwise (see
//! `tests/it_db/main.rs`). A test with neither would run beside a global
//! sweep and flake.
//!
//! Nextest ignores those attributes (one process per test), so
//! `.config/nextest.toml` names every `serial(world)` test in its
//! `threads-required = "num-test-threads"` override; the second guard keeps
//! that list and the attributes in step.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const SERIAL: &str = "#[serial_test::serial(world)]";
const EXCLUSIVE: &str = "threads-required = \"num-test-threads\"";

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

fn it_db_sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it_db");
    let mut sources: Vec<(String, String)> = fs::read_dir(&dir)
        .expect("tests/it_db is readable")
        .map(|entry| entry.expect("tests/it_db entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path: PathBuf| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("UTF-8 name")
                .to_string();
            (
                name,
                fs::read_to_string(&path).expect("test source is UTF-8"),
            )
        })
        .collect();
    sources.sort();
    sources
}

#[test]
fn every_it_db_test_declares_its_world_isolation() {
    let mut offenders = Vec::new();
    let mut tests_seen = 0;
    for (name, source) in it_db_sources() {
        tests_seen += source.lines().filter(|l| is_test_attr(l.trim())).count();
        offenders.extend(undeclared(&name, &source));
    }
    assert!(tests_seen > 0, "scanned no tests in tests/it_db");
    assert!(
        offenders.is_empty(),
        "these it_db tests declare neither {ISOLATION:?}: {offenders:?}"
    );
}

/// `module::fn` of every test in `source` whose attribute block carries
/// `serial(world)` — the name nextest gives it inside the `it_db` binary.
fn serial_tests(module: &str, source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let mut names = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if *line != SERIAL {
            continue;
        }
        let Some(signature) = lines[index..]
            .iter()
            .find(|l| !l.starts_with("#[") && !l.starts_with("//"))
        else {
            continue;
        };
        let name = signature
            .split("fn ")
            .nth(1)
            .and_then(|rest| rest.split(['(', '<']).next())
            .expect("a serial(world) attribute precedes a fn");
        names.push(format!("{module}::{name}"));
    }
    names
}

/// The `test(=…)` names in the nextest override that makes a test run alone.
fn exclusive_in_nextest(config: &str) -> BTreeSet<String> {
    let block = config
        .split("[[profile.default.overrides]]")
        .skip(1)
        .find(|block| block.contains(EXCLUSIVE))
        .expect("nextest.toml has a num-test-threads override");
    block
        .split("test(=")
        .skip(1)
        .filter_map(|rest| rest.split(')').next())
        .map(str::to_string)
        .collect()
}

#[test]
fn every_serial_world_test_runs_alone_under_nextest() {
    let declared: BTreeSet<String> = it_db_sources()
        .iter()
        .flat_map(|(name, source)| serial_tests(name.trim_end_matches(".rs"), source))
        .collect();
    let config =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(".config/nextest.toml"))
            .expect(".config/nextest.toml is readable");
    let listed = exclusive_in_nextest(&config);
    let missing: Vec<_> = declared.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&declared).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "`.config/nextest.toml`'s num-test-threads override must name exactly the \
         serial(world) tests — add {missing:?}, remove {stale:?}"
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

#[test]
fn serial_names_come_from_the_fn_after_the_attribute() {
    let source = "#[tokio::test]\n#[serial_test::serial(world)]\nasync fn sweeps() {}\n\
                  #[tokio::test]\n#[serial_test::parallel(world)]\nasync fn reads() {}\n";
    assert_eq!(serial_tests("m", source), vec!["m::sweeps"]);
}
