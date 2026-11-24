//! Agent-doc drift: facts the agent docs restate must match the tree.
//! Offline — reads files, never boots anything.
//!
//! - every "N default services" (or "all N services") in the agent and
//!   contributor docs equals the number of profile-less services in
//!   `docker-compose.dev.yml`;
//! - `CLAUDE.md`'s Commands table names only `bin/` scripts that exist, and
//!   names every one of them (`bin/lib/` holds sourced helpers, not commands).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;

/// Docs that state the dev-stack size. Plus every `.md` under `.claude/`.
const COUNT_DOCS: &[&str] = &[
    "CLAUDE.md",
    ".github/CLAUDE.md",
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

#[test]
fn stated_dev_stack_size_matches_compose() {
    let expected = default_services().len();
    let re = Regex::new(
        r"(?i)\b(all\s+)?(zero|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+(default\s+|dependency\s+|dev[- ]stack\s+)?(?:compose\s+|dev\s+|db\s+)?(?:services|service\s+containers)\b",
    )
    .expect("regex compiles");

    let mut docs: Vec<PathBuf> = COUNT_DOCS.iter().map(PathBuf::from).collect();
    markdown_under(Path::new(".claude"), &mut docs);

    let mut wrong = Vec::new();
    for doc in &docs {
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
fn commands_table_names_exactly_the_bin_scripts() {
    let claude = read(Path::new("CLAUDE.md"));
    let start = claude
        .find("## Commands")
        .expect("CLAUDE.md has a Commands section");
    let section = &claude[start..];
    let section = section[3..]
        .find("\n## ")
        .map_or(section, |end| &section[..end + 3]);

    let re = Regex::new(r"\bbin/([A-Za-z0-9_-]+)").expect("regex compiles");
    let named: BTreeSet<String> = re.captures_iter(section).map(|c| c[1].to_owned()).collect();

    let on_disk: BTreeSet<String> = fs::read_dir(root().join("bin"))
        .expect("bin/ is readable")
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    let missing: Vec<_> = named.difference(&on_disk).collect();
    assert!(
        missing.is_empty(),
        "CLAUDE.md Commands names bin/ scripts that do not exist: {missing:?}"
    );
    let unnamed: Vec<_> = on_disk.difference(&named).collect();
    assert!(
        unnamed.is_empty(),
        "bin/ scripts missing from CLAUDE.md's Commands table: {unnamed:?}"
    );
}
