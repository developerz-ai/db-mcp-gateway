//! Guard for the public tree: this repository is public, so every tracked file
//! is a public document. None of the rules below is about a credential; each
//! is about a fact of the organisation's own infrastructure that a stranger
//! has no use for and that nothing here needs to build, test or use the
//! project.
//!
//! - **No internal host on our own domain.** Only the public site may be
//!   named; any other subdomain is a service that serves our infrastructure.
//! - **No production deployment's tenant or host.** The plans refer to the
//!   two production clusters as D1 and D2.
//! - **No name of the setup mode that wrote the agent files.**
//! - **No CI provider of the organisation's private repositories.** Naming it
//!   publishes how CI is routed between providers.
//! - **No private repository.** A reference to a `developerz-ai/` repository
//!   names one on the public allowlist below.
//! - **No one's machine.** A path under a home directory names a person and
//!   lays out their machine.
//! - **Every agent and skill file says whose it is.** The preamble that named
//!   the setup mode was replaced with a marker; a file copied back from a
//!   sibling repository would not carry it.
//!
//! Every forbidden value is assembled from parts, so this file never carries
//! one, and a failure names the file and the rule — never the matched text,
//! because CI logs are public. The values are in the history already; what the
//! guard buys is that the tree stops carrying them again.
//!
//! Git is the oracle for "tracked": a real `git ls-files`, after checking that
//! git answers for this checkout and not for an outer repository. `.dz/` is
//! excluded: the platform rewrites those files whole, so a rule there would
//! fail the platform's commits rather than a change made here.
//!
//! The rules are plain functions; the `fires_on_*` tests prove each one can
//! fail. A guard that cannot fail is not a guard.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;

/// This file, repo-relative: the sentinel that proves the scan read the tree
/// it meant to.
const SELF: &str = "tests/public_tree.rs";

/// The fewest tracked files a real checkout of this repository has. A scan
/// that reads fewer read the wrong tree or a sparse one.
const MIN_TRACKED: usize = 300;

/// Rewritten whole by the platform on every run; see the module docs.
const PLATFORM_OWNED: &[&str] = &[".dz/"];

/// The organisation's repositories a tracked file may name: public ones.
const PUBLIC_REPOS: &[&str] = &["db-mcp-gateway", "wurk"];

/// The hosts on our own domain a tracked file may name.
const PUBLIC_HOSTS: &[&str] = &["www.developerz.ai"];

/// The marker this repository's own agent and skill files carry.
const MARKER: &str = "owned by this repository's maintainers";

static OWN_HOST: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?i)\b(?:[a-z0-9-]+\.)+developerz\.ai\b"));

static ORG_REPO: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?i)\bdeveloperz-ai/([a-z0-9_.-]+)"));

static HOME_PATH: LazyLock<Regex> =
    LazyLock::new(|| compiled(r"(?:^|[^\w.-])/(?:home|Users)/[\w.-]+"));

/// Words that must not appear anywhere, case-insensitively, each built from
/// parts: the setup mode, the private CI provider, D2's tenant and its host.
static FORBIDDEN_WORDS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("setup-mode name", ["dz", "runner"].join("-")),
        ("private CI provider", ["ubi", "cloud"].join("")),
        ("production tenant", ["te", "sote"].join("")),
        ("production host", ["miami", "beach", "start"].join("")),
    ]
    .into_iter()
    .map(|(rule, word)| (rule, compiled(&format!("(?i){}", regex::escape(&word)))))
    .collect()
});

fn compiled(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|err| panic!("guard pattern must compile: {err}"))
}

/// The names of every rule `content` breaks. Never the matched text.
fn violations(path: &str, content: &str) -> Vec<&'static str> {
    let mut broken = Vec::new();
    let names_internal_host = OWN_HOST
        .find_iter(content)
        .any(|m| !PUBLIC_HOSTS.contains(&m.as_str().to_ascii_lowercase().as_str()));
    if names_internal_host {
        broken.push("internal host on our own domain");
    }
    broken.extend(
        FORBIDDEN_WORDS
            .iter()
            .filter(|(_, word)| word.is_match(content))
            .map(|(rule, _)| *rule),
    );
    let names_private_repo = ORG_REPO.captures_iter(content).any(|caps| {
        // GitHub owner and repository names are case-insensitive.
        let name = caps[1].to_ascii_lowercase();
        let name = name.trim_end_matches('.');
        let name = name.strip_suffix(".git").unwrap_or(name);
        !PUBLIC_REPOS.contains(&name)
    });
    if names_private_repo {
        broken.push("private repository");
    }
    if HOME_PATH.is_match(content) {
        broken.push("home directory path");
    }
    if carries_preamble(path) && !content.contains(MARKER) {
        broken.push("agent or skill file without this repository's marker");
    }
    broken
}

fn carries_preamble(path: &str) -> bool {
    let agent = path.starts_with(".claude/agents/") && path.ends_with(".md");
    let skill = path.starts_with(".claude/skills/") && path.ends_with("/SKILL.md");
    agent || skill
}

fn git(root: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|err| panic!("git {args:?} must run: {err}"));
    assert!(
        out.status.success(),
        "git {args:?} exited {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    out.stdout
}

/// The checkout root, confirmed by git itself: a checkout nested in another
/// repository would have git answer with the outer tree's index.
fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let toplevel = git(&manifest, &["rev-parse", "--show-toplevel"]);
    let toplevel = PathBuf::from(String::from_utf8_lossy(&toplevel).trim());
    let canonical = |p: &Path| {
        p.canonicalize()
            .unwrap_or_else(|err| panic!("{} must resolve: {err}", p.display()))
    };
    assert_eq!(
        canonical(&toplevel),
        canonical(&manifest),
        "git answers for another repository; the scan would read a tree that is not this one"
    );
    manifest
}

fn tracked_files(root: &Path) -> Vec<String> {
    String::from_utf8_lossy(&git(root, &["ls-files", "-z"]))
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn no_tracked_file_carries_internal_infrastructure() {
    let root = repo_root();
    let tracked = tracked_files(&root);
    assert!(
        tracked.iter().any(|path| path == SELF),
        "git ls-files does not list {SELF}: the scan is not reading this tree"
    );

    let mut read = 0;
    let mut failures = Vec::new();
    for path in &tracked {
        if PLATFORM_OWNED.iter().any(|dir| path.starts_with(dir)) {
            continue;
        }
        let full = root.join(path);
        if full.is_dir() {
            continue; // a submodule entry, not a file
        }
        let bytes =
            std::fs::read(&full).unwrap_or_else(|err| panic!("tracked {path} must read: {err}"));
        read += 1;
        let content = String::from_utf8_lossy(&bytes);
        failures.extend(
            violations(path, &content)
                .into_iter()
                .map(|rule| format!("{path}: {rule}")),
        );
    }

    eprintln!(
        "public-tree guard read {read} of {} tracked files",
        tracked.len()
    );
    assert!(
        read >= MIN_TRACKED,
        "read only {read} tracked files; expected at least {MIN_TRACKED}"
    );
    assert!(
        failures.is_empty(),
        "tracked files carry internal infrastructure (rule per file, value withheld):\n{}",
        failures.join("\n")
    );
}

#[test]
fn passes_public_references() {
    let content = "See https://www.developerz.ai, email security@developerz.ai, \
                   pull ghcr.io/developerz-ai/db-mcp-gateway, clone \
                   developerz-ai/db-mcp-gateway.git, cache under ~/.cargo/registry.";
    assert_eq!(violations("README.md", content), Vec::<&str>::new());
}

#[test]
fn fires_on_internal_host() {
    let host = ["svc", "developerz", "ai"].join(".");
    assert_eq!(
        violations("a.md", &format!("url: https://{host}/v1")),
        ["internal host on our own domain"]
    );
}

#[test]
fn fires_on_each_forbidden_word() {
    for (rule, word) in [
        ("setup-mode name", ["DZ", "RUNNER"].join("-")),
        ("private CI provider", ["Ubi", "cloud"].join("")),
        ("production tenant", ["te", "sote"].join("")),
        ("production host", ["miami", "beach", "start"].join("")),
    ] {
        assert_eq!(violations("a.md", &format!("x {word} y")), [rule]);
    }
}

#[test]
fn fires_on_private_repository() {
    for repo in [["developerz-ai", "infra"], ["Developerz-AI", "Infra"]] {
        let repo = repo.join("/");
        assert_eq!(
            violations("a.md", &format!("see `{repo}`.")),
            ["private repository"]
        );
    }
    let public = ["Developerz-AI", "DB-MCP-Gateway"].join("/");
    assert!(violations("a.md", &public).is_empty());
}

#[test]
fn fires_on_home_directory() {
    let path = ["", "home", "someone", "src"].join("/");
    assert_eq!(
        violations("a.md", &format!("cd {path}")),
        ["home directory path"]
    );
}

#[test]
fn fires_on_agent_file_without_marker() {
    assert_eq!(
        violations(".claude/agents/x.md", "> Specialist definition."),
        ["agent or skill file without this repository's marker"]
    );
    assert_eq!(
        violations(".claude/skills/x/SKILL.md", "> House skill."),
        ["agent or skill file without this repository's marker"]
    );
    assert!(violations(".claude/commands/x.md", "no marker needed").is_empty());
}
