//! Agent-doc drift: facts the agent docs restate must match the tree.
//! Offline — reads files, never boots anything.
//!
//! - the root `CLAUDE.md` stays under 10 000 bytes, and every scoped
//!   `CLAUDE.md` it points to exists;
//! - every "N default services" (or "all N services") in the agent and
//!   contributor docs equals the number of profile-less services in
//!   `docker-compose.dev.yml`;
//! - the Commands tables of the `CLAUDE.md` family name only `bin/` scripts
//!   that exist, and each of them on exactly one row (`bin/lib/` holds sourced
//!   helpers, not commands);
//! - a doc that names the latest migration names the newest file of the
//!   directory it means (`migrations/` or `migrations-mysql/`; either one when
//!   the claim does not say);
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

/// Scripts a Commands section lists, one entry per row that names them: a row
/// may repeat a script (`bin/fmt` / `bin/fmt --changed`), two rows may not.
fn scripts_by_row(section: &str) -> Vec<String> {
    section.lines().flat_map(bin_scripts_named).collect()
}

/// `(script, doc)` listings → the scripts listed, and those on more than one row.
fn split_listings(listings: &[(String, String)]) -> (BTreeSet<String>, Vec<String>) {
    let mut owner: BTreeMap<&str, &str> = BTreeMap::new();
    let mut twice = Vec::new();
    for (script, doc) in listings {
        if let Some(first) = owner.insert(script, doc) {
            twice.push(format!("bin/{script}: {first} and {doc}"));
        }
    }
    (owner.into_keys().map(str::to_owned).collect(), twice)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Postgres,
    Mysql,
}

/// "The latest migration is `number`", for `backend` when the claim names one.
#[derive(Debug, PartialEq, Eq)]
struct LatestClaim {
    backend: Option<Backend>,
    number: u32,
}

/// Highest `NNNN_` prefix among the migrations of `backend`.
fn latest_migration(backend: Backend) -> u32 {
    let dir = match backend {
        Backend::Postgres => "migrations",
        Backend::Mysql => "migrations-mysql",
    };
    fs::read_dir(root().join(dir))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().get(..4)?.parse().ok())
        .max()
        .unwrap_or_else(|| panic!("{dir} has no numbered migration"))
}

/// The last backend or migrations directory `text` names.
fn last_backend(text: &str) -> Option<Backend> {
    let re =
        Regex::new(r"(?i)mysql|migrations[/`]|postgres|\bstate[- ]db\b").expect("regex compiles");
    re.find_iter(text).last().map(|m| {
        if m.as_str().eq_ignore_ascii_case("mysql") {
            Backend::Mysql
        } else {
            Backend::Postgres
        }
    })
}

/// Migrations a text claims are the latest ("latest migration 0021", "newest
/// MySQL migration is `0006`", "latest migrations: 0021 (Postgres), 0006 (MySQL)").
fn claimed_latest_migrations(text: &str) -> Vec<LatestClaim> {
    let claim = Regex::new(
        r"(?i)\b(?:latest|newest|highest|last)\s+(?:(?:state[- ]DB|MySQL|Postgres|permissions[- ]store)\s+){0,2}`?migrations?\b[^.\n]{0,40}?(\d{4})",
    )
    .expect("regex compiles");
    // A further number belongs to the claim only when joined to the previous one.
    let joined = Regex::new(
        r"(?i)^\s*(?:,|/|&|\+|\band\b)(?:[\s`,/]|\b(?:and|the|for|in|is|state[- ]DB|MySQL|Postgres|migrations(?:-mysql)?)\b)*(\d{4})",
    )
    .expect("regex compiles");
    // What may follow a number: the rest of its file name, then its backend.
    let file_name = Regex::new(r"^(?:_\w+)?(?:\.sql)?`?").expect("regex compiles");
    let suffix = Regex::new(
        r"(?i)^\s*(?:\(|in\s|for\s|on\s)\s*(?:the\s+)?`?(?:MySQL|Postgres|state[- ]DB|migrations(?:-mysql)?[/`])[^\w,;(]*",
    )
    .expect("regex compiles");

    let mut claims = Vec::new();
    for sentence in text.split(['\n', ';']).flat_map(|line| line.split(". ")) {
        let mut pos = 0;
        while let Some(first) = claim.captures(&sentence[pos..]) {
            let mut before = pos;
            let mut digits = first.get(1).expect("group").range();
            loop {
                let (start, end) = (pos + digits.start, pos + digits.end);
                let name_end = end + file_name.find(&sentence[end..]).map_or(0, |m| m.end());
                let after = suffix.find(&sentence[name_end..]);
                claims.push(LatestClaim {
                    backend: after
                        .and_then(|m| last_backend(m.as_str()))
                        .or_else(|| last_backend(&sentence[before..start])),
                    number: sentence[start..end].parse().expect("four digits"),
                });
                pos = name_end + after.map_or(0, |m| m.end());
                before = pos;
                let Some(next) = joined.captures(&sentence[pos..]) else {
                    break;
                };
                digits = next.get(1).expect("group").range();
            }
        }
    }
    claims
}

/// The claims that match neither their own directory nor, unqualified, any.
fn stale_claims(claims: Vec<LatestClaim>, postgres: u32, mysql: u32) -> Vec<LatestClaim> {
    claims
        .into_iter()
        .filter(|claim| match claim.backend {
            Some(Backend::Postgres) => claim.number != postgres,
            Some(Backend::Mysql) => claim.number != mysql,
            None => ![postgres, mysql].contains(&claim.number),
        })
        .collect()
}

/// A markdown block, as far as the required-check guard tells them apart.
#[derive(Debug)]
enum Block {
    /// A paragraph or a heading.
    Text(String),
    Item {
        indent: usize,
        text: String,
    },
    Row {
        header: bool,
        text: String,
    },
}

impl Block {
    fn text(&self) -> &str {
        match self {
            Block::Text(text) | Block::Item { text, .. } | Block::Row { text, .. } => text,
        }
    }
}

fn blocks(doc: &str) -> Vec<Block> {
    let item = Regex::new(r"^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$").expect("regex compiles");
    let heading = Regex::new(r"^#{1,6}\s").expect("regex compiles");
    let mut out: Vec<Block> = Vec::new();
    // Whether the next line may continue the last block.
    let mut open = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            open = false;
        } else if trimmed.starts_with('|') {
            let header = !(open && matches!(out.last(), Some(Block::Row { .. })));
            let text = trimmed.to_owned();
            out.push(Block::Row { header, text });
            open = true;
        } else if let Some(caps) = item.captures(line) {
            let (indent, text) = (caps[1].len(), caps[2].to_owned());
            out.push(Block::Item { indent, text });
            open = true;
        } else if heading.is_match(line) {
            out.push(Block::Text(trimmed.to_owned()));
            open = false;
        } else {
            match out.last_mut() {
                Some(Block::Text(text) | Block::Item { text, .. }) if open => {
                    text.push(' ');
                    text.push_str(trimmed);
                }
                _ => out.push(Block::Text(trimmed.to_owned())),
            }
            open = true;
        }
    }
    out
}

/// How many of the blocks after `block` it introduces: the list or table under
/// a paragraph, the nested items under an item, the body under a table header.
fn introduced(block: &Block, rest: &[Block]) -> usize {
    let body_rows = |rows: &[Block]| {
        rows.iter()
            .take_while(|b| matches!(b, Block::Row { header: false, .. }))
            .count()
    };
    match (block, rest.first()) {
        (Block::Text(_), Some(Block::Item { .. })) => rest
            .iter()
            .take_while(|b| matches!(b, Block::Item { .. }))
            .count(),
        (Block::Text(_), Some(Block::Row { .. })) => 1 + body_rows(&rest[1..]),
        (Block::Item { indent, .. }, _) => rest
            .iter()
            .take_while(|b| matches!(b, Block::Item { indent: i, .. } if i > indent))
            .count(),
        (Block::Row { header: true, .. }, _) => body_rows(rest),
        _ => 0,
    }
}

/// `ci.yml` jobs `text` names: in backticks, or as a whole list entry or cell.
fn jobs_named(text: &str, jobs: &BTreeSet<String>) -> BTreeSet<String> {
    let ticked = Regex::new(r"`([A-Za-z0-9_-]+)`").expect("regex compiles");
    let separator = Regex::new(r"[,;:|\n—]|\band\b").expect("regex compiles");
    ticked
        .captures_iter(text)
        .map(|c| c[1].to_owned())
        .chain(separator.split(text).map(|piece| {
            piece
                .trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_owned()
        }))
        .filter(|name| jobs.contains(name))
        .collect()
}

/// Blocks that mention required checks and name two or more `ci.yml` jobs — in
/// one sentence, one table row, or the list or table the block introduces: a
/// restated required-check list.
fn required_check_lists(text: &str, jobs: &BTreeSet<String>) -> Vec<String> {
    let mention =
        Regex::new(r"(?i)\brequired[- ](?:status[- ])?checks?\b").expect("regex compiles");
    // "the single required check" says there is one, so the other jobs in its
    // row are not a list of them.
    let single =
        Regex::new(r"(?i)\b(?:single|sole|only)\s+required[- ]check\b").expect("regex compiles");
    let is_list = |unit: &str| jobs_named(unit, jobs).len() >= 2;

    let blocks = blocks(text);
    let mut lists = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let own = block.text();
        let rest = &blocks[i + 1..];
        let count = introduced(block, rest);
        let sentence = own
            .split('|')
            .flat_map(|cell| cell.split(". "))
            .any(|s| mention.is_match(s) && is_list(s));
        let grouped = count > 0 || matches!(block, Block::Row { .. });
        let group = grouped && mention.is_match(&single.replace_all(own, "")) && {
            let unit: Vec<&str> = std::iter::once(own)
                .chain(rest[..count].iter().map(Block::text))
                .collect();
            is_list(&unit.join("\n"))
        };
        if sentence || group {
            lists.push(own.to_owned());
        }
    }
    lists
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
    let mut listings = Vec::new();
    for doc in claude_family() {
        let text = read(&doc);
        let Some(section) = commands_section(&text) else {
            continue;
        };
        for script in scripts_by_row(section) {
            listings.push((script, doc.display().to_string()));
        }
    }
    let (named, twice) = split_listings(&listings);
    assert!(
        twice.is_empty(),
        "bin/ scripts listed on more than one Commands row (tell each once):\n{}",
        twice.join("\n")
    );

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
fn repeated_command_rows_are_detected() {
    let listed = |section: &str| -> Vec<(String, String)> {
        scripts_by_row(section)
            .into_iter()
            .map(|script| (script, "CLAUDE.md".to_owned()))
            .collect()
    };
    let one_row = listed("| Format / changed | `bin/fmt` / `bin/fmt --changed` |\n");
    assert_eq!(
        split_listings(&one_row),
        (BTreeSet::from(["fmt".to_owned()]), vec![])
    );
    let two_rows = listed("| Format | `bin/fmt` |\n| Changed | `bin/fmt --changed` |\n");
    assert_eq!(
        split_listings(&two_rows).1,
        ["bin/fmt: CLAUDE.md and CLAUDE.md"]
    );
}

#[test]
fn stated_latest_migration_matches_the_tree() {
    let postgres = latest_migration(Backend::Postgres);
    let mysql = latest_migration(Backend::Mysql);
    let mut wrong = Vec::new();
    for doc in &fact_docs() {
        for claim in stale_claims(claimed_latest_migrations(&read(doc)), postgres, mysql) {
            wrong.push(format!("{}: {claim:?}", doc.display()));
        }
    }
    assert!(
        wrong.is_empty(),
        "latest migrations are {:04} (migrations/) and {:04} (migrations-mysql/); these docs say otherwise:\n{}",
        postgres,
        mysql,
        wrong.join("\n")
    );
}

#[test]
fn latest_migration_claims_are_detected() {
    use Backend::{Mysql, Postgres};
    let claims = |text: &str| -> Vec<(Option<Backend>, u32)> {
        claimed_latest_migrations(text)
            .into_iter()
            .map(|c| (c.backend, c.number))
            .collect()
    };
    for (text, expected) in [
        ("the latest migration is `0021`", vec![(None, 21)]),
        ("newest MySQL migration 0006", vec![(Some(Mysql), 6)]),
        (
            "latest Postgres migration: 0021",
            vec![(Some(Postgres), 21)],
        ),
        (
            "latest migration `migrations/0021_x.sql`",
            vec![(Some(Postgres), 21)],
        ),
        (
            "latest migration `migrations-mysql/0006_x.sql`",
            vec![(Some(Mysql), 6)],
        ),
        (
            "latest migration in `migrations-mysql/` is 0006",
            vec![(Some(Mysql), 6)],
        ),
        (
            "the latest `migrations-mysql/` file is 0006",
            vec![(Some(Mysql), 6)],
        ),
        (
            "On MySQL the latest migration is 0006",
            vec![(Some(Mysql), 6)],
        ),
        ("latest migration is 0006 (MySQL)", vec![(Some(Mysql), 6)]),
        ("latest migration 0021/0006", vec![(None, 21), (None, 6)]),
        (
            "latest migrations: 0021 (Postgres) and 0006 (MySQL)",
            vec![(Some(Postgres), 21), (Some(Mysql), 6)],
        ),
        (
            "latest migration is `migrations/0021`, `migrations-mysql/0006`",
            vec![(Some(Postgres), 21), (Some(Mysql), 6)],
        ),
        (
            "latest migration 0021 in `migrations/` and 0006 in `migrations-mysql/`",
            vec![(Some(Postgres), 21), (Some(Mysql), 6)],
        ),
        ("see `migrations/0011_*` → `0015_*`", vec![]),
    ] {
        assert_eq!(claims(text), expected, "{text}");
    }
}

#[test]
fn a_qualified_claim_is_compared_with_its_own_directory() {
    let stale = |text: &str| stale_claims(claimed_latest_migrations(text), 27, 8).len();
    assert_eq!(stale("latest MySQL migration is 0008"), 0);
    assert_eq!(stale("latest MySQL migration is 0027"), 1);
    assert_eq!(stale("latest Postgres migration is 0027"), 0);
    assert_eq!(stale("latest Postgres migration is 0008"), 1);
    assert_eq!(stale("latest migration `migrations-mysql/0027_x.sql`"), 1);
    assert_eq!(stale("latest migrations: 0027 (Postgres), 0027 (MySQL)"), 1);
    assert_eq!(stale("latest migration 0027/0008"), 0);
    assert_eq!(stale("latest migration 0021"), 1);
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
    let jobs: BTreeSet<String> = ["fmt", "test", "gate", "changes"].map(str::to_owned).into();
    for text in [
        "Required checks: `fmt`, `test`.",
        "Required checks: fmt and test",
        "Required checks:\n\n- `fmt`\n- `test`\n",
        "Required checks:\n- fmt\n- test\n",
        "Required checks:\n\n1. `fmt`\n\n2. `test`\n",
        "The required status checks\non main are:\n\n* **fmt**: rustfmt\n* **test**: nextest\n",
        "## Required checks\n\n- [ ] `fmt`\n- [ ] test\n",
        "- Required checks:\n  - `fmt`\n  - `test`\n",
        "| What | Jobs |\n|---|---|\n| Required checks | `fmt`, `test` |\n",
        "| What | A | B |\n|---|---|---|\n| Required checks | fmt | test |\n",
        "| Required check |\n|---|\n| `fmt` |\n| `test` |\n",
        "Required checks:\n\n| Job |\n|---|\n| `fmt` |\n| `test` |\n",
    ] {
        assert_eq!(required_check_lists(text, &jobs).len(), 1, "{text}");
    }
    for text in [
        "`gate` is the single required check.",
        "| `gate` | a skip `changes` ordered. The single required check once the rest retires |",
        "- Green required checks merge.\n- `fmt` is fast.\n- `test` is not.\n",
        "Required checks live in the ruleset.\n\nJobs:\n\n- `fmt`\n- `test`\n",
        "| Job | Does |\n|---|---|\n| `fmt` | a required check |\n| `test` | nextest |\n",
    ] {
        assert!(required_check_lists(text, &jobs).is_empty(), "{text}");
    }
}
