//! Agent-doc drift: facts the agent docs restate must match the tree.
//! Offline — reads files, never boots anything.
//!
//! - the root `CLAUDE.md` stays under 10 000 bytes, and every scoped
//!   `CLAUDE.md` it points to exists;
//! - every "N default services" (or "all N services") in the agent and
//!   contributor docs equals the number of profile-less services in
//!   `docker-compose.dev.yml`;
//! - the Commands tables of the `CLAUDE.md` family name only `bin/` scripts
//!   that exist, and each of them exactly once (`bin/lib/` holds sourced
//!   helpers, not commands);
//! - a doc that names the latest migration names the newest file in
//!   `migrations/` or `migrations-mysql/`;
//! - no agent doc re-declares the required-check list (`.github/CLAUDE.md`
//!   §Rules: GitHub's live rulesets are the only authority).

// CLAUDE.md §Conventions: tests may panic; `[lints.clippy]` denies it for shipped code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use serde::de::IgnoredAny;

/// Root `CLAUDE.md` budget: it loads into every session.
const ROOT_BUDGET_BYTES: usize = 10_000;

/// Scoped `CLAUDE.md` files the root must point to.
const REQUIRED_SCOPED: &[&str] = &[
    "src/CLAUDE.md",
    "tests/CLAUDE.md",
    "bin/CLAUDE.md",
    ".github/CLAUDE.md",
    "third_party/CLAUDE.md",
];

/// Non-`CLAUDE.md` docs that state facts. Plus the `CLAUDE.md` family and
/// every `.md` under `.claude/`.
const OTHER_DOCS: &[&str] = &[
    "CONTRIBUTING.md",
    "README.md",
    "AGENTS.md",
    "bin/dev",
    "bin/setup",
    "bin/test",
];

#[derive(Debug, Deserialize)]
struct Compose {
    services: BTreeMap<String, Service>,
}

#[derive(Debug, Deserialize)]
struct Service {
    #[serde(default)]
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Workflow {
    jobs: BTreeMap<String, IgnoredAny>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &Path) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {}: {e}", rel.display()))
}

fn markdown_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root().join(dir)).unwrap_or_else(|e| panic!("{dir:?}: {e}"));
    for entry in entries.flatten() {
        let rel = dir.join(entry.file_name());
        if entry.path().is_dir() {
            markdown_under(&rel, out);
        } else if rel.extension().is_some_and(|e| e == "md") {
            out.push(rel);
        }
    }
}

/// Paths of the scoped `CLAUDE.md` files the root links to.
fn scoped_claude_mds() -> BTreeSet<String> {
    let re = Regex::new(r"\]\(([A-Za-z0-9_./-]+/CLAUDE\.md)\)").expect("regex compiles");
    re.captures_iter(&read(Path::new("CLAUDE.md")))
        .map(|c| c[1].to_owned())
        .collect()
}

/// Root `CLAUDE.md` first, then every scoped one it points to.
fn claude_family() -> Vec<PathBuf> {
    std::iter::once("CLAUDE.md".to_owned())
        .chain(scoped_claude_mds())
        .map(PathBuf::from)
        .collect()
}

/// Every doc whose restated facts are checked.
fn fact_docs() -> Vec<PathBuf> {
    let mut docs = claude_family();
    docs.extend(OTHER_DOCS.iter().map(PathBuf::from));
    markdown_under(Path::new(".claude"), &mut docs);
    docs
}

fn default_services() -> BTreeSet<String> {
    let compose: Compose = serde_saphyr::from_str(&read(Path::new("docker-compose.dev.yml")))
        .expect("docker-compose.dev.yml parses");
    compose
        .services
        .into_iter()
        .filter(|(_, service)| service.profiles.is_empty())
        .map(|(name, _)| name)
        .collect()
}

fn number(word: &str) -> usize {
    const WORDS: [&str; 11] = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
    ];
    WORDS
        .iter()
        .position(|w| w.eq_ignore_ascii_case(word))
        .or_else(|| word.parse().ok())
        .unwrap_or_else(|| panic!("not a number: {word}"))
}

/// The `## Commands` section of a markdown doc, if it has one.
fn commands_section(doc: &str) -> Option<&str> {
    let start = doc.find("## Commands")?;
    let section = &doc[start..];
    Some(
        section[3..]
            .find("\n## ")
            .map_or(section, |end| &section[..end + 3]),
    )
}

/// `bin/<script>` names in `text`; `bin/CLAUDE.md`-style file names are not scripts.
fn bin_scripts_named(text: &str) -> BTreeSet<String> {
    let re = Regex::new(r"\bbin/([A-Za-z0-9_-]+)(\.[A-Za-z]+)?").expect("regex compiles");
    re.captures_iter(text)
        .filter(|c| c.get(2).is_none())
        .map(|c| c[1].to_owned())
        .collect()
}

/// Highest `NNNN_` prefix among the files in `dir`.
fn latest_migration(dir: &str) -> u32 {
    fs::read_dir(root().join(dir))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().get(..4)?.parse().ok())
        .max()
        .unwrap_or_else(|| panic!("{dir} has no numbered migration"))
}

/// Migration numbers a text claims are the latest ("latest migration 0021",
/// "newest MySQL migration is `0006`").
fn claimed_latest_migrations(text: &str) -> Vec<u32> {
    let re = Regex::new(
        r"(?i)\b(?:latest|newest|highest|last)\s+(?:state[- ]DB\s+|MySQL\s+|Postgres\s+|permissions[- ]store\s+)?migrations?\b[^.\n]{0,40}?`?(?:migrations(?:-mysql)?/)?(\d{4})",
    )
    .expect("regex compiles");
    re.captures_iter(text)
        .map(|c| c[1].parse().expect("four digits"))
        .collect()
}

/// Sentences that mention a required check and name two or more `ci.yml` jobs:
/// a restated required-check list.
fn required_check_lists(text: &str, jobs: &BTreeSet<String>) -> Vec<String> {
    let job = Regex::new(r"`([A-Za-z0-9_-]+)`").expect("regex compiles");
    text.split(['\n', '|'])
        .flat_map(|line| line.split(". "))
        .filter(|s| s.to_ascii_lowercase().contains("required check"))
        .filter(|s| {
            let named: BTreeSet<&str> = job
                .captures_iter(s)
                .map(|c| c.get(1).expect("group").as_str())
                .filter(|name| jobs.contains(*name))
                .collect();
            named.len() >= 2
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn root_claude_md_fits_the_budget() {
    let size = read(Path::new("CLAUDE.md")).len();
    assert!(
        size < ROOT_BUDGET_BYTES,
        "CLAUDE.md is {size} bytes; keep it under {ROOT_BUDGET_BYTES} — move detail into a scoped CLAUDE.md"
    );
}

#[test]
fn scoped_claude_mds_the_root_points_to_exist() {
    let pointed = scoped_claude_mds();
    let unlinked: Vec<_> = REQUIRED_SCOPED
        .iter()
        .filter(|p| !pointed.contains(**p))
        .collect();
    assert!(
        unlinked.is_empty(),
        "CLAUDE.md does not link these scoped docs: {unlinked:?}"
    );
    let missing: Vec<_> = pointed
        .iter()
        .filter(|p| !root().join(p).is_file())
        .collect();
    assert!(
        missing.is_empty(),
        "CLAUDE.md points to missing files: {missing:?}"
    );
}

#[test]
fn stated_dev_stack_size_matches_compose() {
    let expected = default_services().len();
    let re = Regex::new(
        r"(?i)\b(all\s+)?(zero|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+(default\s+|dependency\s+|dev[- ]stack\s+)?(?:compose\s+|dev\s+|db\s+)?(?:services|service\s+containers)\b",
    )
    .expect("regex compiles");

    let mut wrong = Vec::new();
    for doc in &fact_docs() {
        for caps in re.captures_iter(&read(doc)) {
            // "two services sit behind profiles" is not a stack-size claim:
            // only "all N …" or "N default/dependency/dev-stack …" is.
            if caps.get(1).is_none() && caps.get(3).is_none() {
                continue;
            }
            if number(&caps[2]) != expected {
                wrong.push(format!("{}: `{}`", doc.display(), &caps[0]));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "docker-compose.dev.yml has {expected} default services ({:?}); these docs say otherwise:\n{}",
        default_services(),
        wrong.join("\n")
    );
}

#[test]
fn commands_tables_name_each_bin_script_once() {
    let mut owner: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut twice = Vec::new();
    for doc in claude_family() {
        let text = read(&doc);
        let Some(section) = commands_section(&text) else {
            continue;
        };
        for script in bin_scripts_named(section) {
            if let Some(first) = owner.insert(script.clone(), doc.clone()) {
                twice.push(format!(
                    "bin/{script}: {} and {}",
                    first.display(),
                    doc.display()
                ));
            }
        }
    }
    assert!(
        twice.is_empty(),
        "bin/ scripts listed in more than one Commands table (tell each once):\n{}",
        twice.join("\n")
    );

    let named: BTreeSet<String> = owner.into_keys().collect();
    let on_disk: BTreeSet<String> = fs::read_dir(root().join("bin"))
        .expect("bin/ is readable")
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.contains('.'))
        .collect();

    let missing: Vec<_> = named.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "Commands tables name bin/ scripts that do not exist: {missing:?}"
    );
    let unnamed: Vec<_> = on_disk.difference(&named).collect();
    assert!(
        unnamed.is_empty(),
        "bin/ scripts missing from every CLAUDE.md Commands table: {unnamed:?}"
    );
}

#[test]
fn stated_latest_migration_matches_the_tree() {
    let latest = [
        latest_migration("migrations"),
        latest_migration("migrations-mysql"),
    ];
    let mut wrong = Vec::new();
    for doc in &fact_docs() {
        for n in claimed_latest_migrations(&read(doc)) {
            if !latest.contains(&n) {
                wrong.push(format!("{}: {n:04}", doc.display()));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "latest migrations are {:04} (migrations/) and {:04} (migrations-mysql/); these docs say otherwise:\n{}",
        latest[0],
        latest[1],
        wrong.join("\n")
    );
}

#[test]
fn latest_migration_claims_are_detected() {
    assert_eq!(
        claimed_latest_migrations("the latest migration is `0021`; newest MySQL migration 0006"),
        [21, 6]
    );
    assert!(claimed_latest_migrations("see `migrations/0011_*` → `0015_*`").is_empty());
}

#[test]
fn no_doc_redeclares_the_required_checks() {
    let workflow: Workflow = serde_saphyr::from_str(&read(Path::new(".github/workflows/ci.yml")))
        .expect("ci.yml parses");
    let jobs: BTreeSet<String> = workflow.jobs.into_keys().collect();

    let mut lists = Vec::new();
    for doc in &fact_docs() {
        for sentence in required_check_lists(&read(doc), &jobs) {
            lists.push(format!("{}: {}", doc.display(), sentence.trim()));
        }
    }
    assert!(
        lists.is_empty(),
        "required checks live in GitHub's rulesets, never in a doc (.github/CLAUDE.md §Rules):\n{}",
        lists.join("\n")
    );
}

#[test]
fn required_check_lists_are_detected() {
    let jobs: BTreeSet<String> = ["fmt", "test", "gate"].map(str::to_owned).into();
    assert_eq!(
        required_check_lists("Required checks: `fmt`, `test`.", &jobs).len(),
        1
    );
    assert!(required_check_lists("`gate` is the single required check.", &jobs).is_empty());
}
