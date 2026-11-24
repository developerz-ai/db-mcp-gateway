"""Guard for the public tree: this repository is public, so every tracked file
is a public document. None of the rules below is about a credential; each is
about a fact of the organisation's own infrastructure that a stranger has no
use for and that nothing here needs to build, test or use the project.

- No internal host on our own domain. Only the public site may be named; any
  other subdomain is a service that serves our infrastructure.
- No name of the setup mode that wrote the agent files.
- No private word. The CI provider of the organisation's private repositories,
  and a production deployment's tenant and host. A committed list publishes
  what it guards, even assembled from parts, so these come from the
  `PUBLIC_TREE_PRIVATE_WORDS` CI secret. A run without it (a fork's pull
  request, a local run) says it skipped them; this repository's own CI runs set
  `PUBLIC_TREE_PRIVATE_WORDS_REQUIRED=1`, where an empty secret fails instead.
- No private repository. A reference to a `developerz-ai/` repository names
  one on the public allowlist below.
- No one's machine. A path under a home directory names a person.
- Every agent and skill file says whose it is (the marker below).

The one forbidden value this file knows itself, the setup mode's name, is
assembled from parts so the guard does not trip over itself. A failure names
the file and the rule, never the matched text: CI logs are public.

Git is the oracle for "tracked", after checking that git answers for this
checkout and not for an outer repository. `.dz/` is excluded: the platform's
setup template rewrites it whole. `.mcp.json` is scanned on purpose.

Run as `python3 -I .github/scripts/public_tree.py`; test_public_tree.py proves
each rule can fail. A guard that cannot fail is not a guard.
"""

import os
import re
import subprocess
import sys

# This file, repo-relative: the sentinel that proves the scan read its tree.
SELF = ".github/scripts/public_tree.py"
# The fewest tracked files a real checkout has; fewer means a wrong or sparse tree.
MIN_TRACKED = 300
# Rewritten whole by the platform. A trailing `/` is a directory prefix.
PLATFORM_OWNED = (".dz/",)
PRIVATE_WORDS_ENV = "PUBLIC_TREE_PRIVATE_WORDS"
PRIVATE_WORDS_REQUIRED_ENV = "PUBLIC_TREE_PRIVATE_WORDS_REQUIRED"
PUBLIC_REPOS = ("db-mcp-gateway", "wurk")
PUBLIC_HOSTS = ("www.developerz.ai",)
MARKER = "owned by this repository's maintainers"

OWN_HOST = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+developerz\.ai\b")
ORG_REPO = re.compile(r"(?i)\bdeveloperz-ai/([a-z0-9_.-]+)")
HOME_PATH = re.compile(r"(?:^|[^\w.-])/(?:home|Users)/[\w.-]+", re.MULTILINE)
FORBIDDEN_WORDS = (
    ("setup-mode name", re.compile(re.escape("-".join(["dz", "runner"])), re.IGNORECASE)),
)


class GuardError(Exception):
    """The scan cannot run or cannot be trusted; never a rule violation."""


def private_words(raw):
    """The secret's words: comma- or newline-separated, trimmed, blanks dropped,
    each matched literally and case-insensitively. Unset or blank is none."""
    words = (word.strip() for word in re.split(r"[,\n]", raw or ""))
    return [re.compile(re.escape(word), re.IGNORECASE) for word in words if word]


def private_words_for_run(raw, required):
    words = private_words(raw)
    if not words and required:
        raise GuardError(
            f"{PRIVATE_WORDS_ENV} is empty, and {PRIVATE_WORDS_REQUIRED_ENV}=1 says "
            "this run must check the private words"
        )
    return words


def names_private_word(content, words):
    """Whether `content` carries any private word. Never which one."""
    return any(word.search(content) for word in words)


def platform_owned(path):
    return any(
        path.startswith(owned) if owned.endswith("/") else path == owned
        for owned in PLATFORM_OWNED
    )


def carries_preamble(path):
    agent = path.startswith(".claude/agents/") and path.endswith(".md")
    skill = path.startswith(".claude/skills/") and path.endswith("/SKILL.md")
    return agent or skill


def _names_private_repo(content):
    for match in ORG_REPO.finditer(content):
        # GitHub owner and repository names are case-insensitive.
        name = match.group(1).lower().rstrip(".")
        name = name.removesuffix(".git")
        if name not in PUBLIC_REPOS:
            return True
    return False


def violations(path, content):
    """The names of every rule `content` breaks. Never the matched text."""
    broken = []
    if any(m.group(0).lower() not in PUBLIC_HOSTS for m in OWN_HOST.finditer(content)):
        broken.append("internal host on our own domain")
    broken.extend(rule for rule, word in FORBIDDEN_WORDS if word.search(content))
    if _names_private_repo(content):
        broken.append("private repository")
    if HOME_PATH.search(content):
        broken.append("home directory path")
    if carries_preamble(path) and MARKER not in content:
        broken.append("agent or skill file without this repository's marker")
    return broken


def _git(root, *args):
    try:
        out = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    except OSError as err:
        raise GuardError(f"git {list(args)} must run: {err}") from err
    if out.returncode != 0:
        stderr = out.stderr.decode(errors="replace").strip()
        raise GuardError(f"git {list(args)} exited {out.returncode}: {stderr}")
    return out.stdout


def repo_root():
    """The checkout root, confirmed by git itself: a checkout nested in another
    repository would have git answer with the outer tree's index."""
    root = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    toplevel = _git(root, "rev-parse", "--show-toplevel").decode().strip()
    if os.path.realpath(toplevel) != root:
        raise GuardError("git answers for another repository; the scan would read another tree")
    return root


def tracked_files(root):
    return [p for p in _git(root, "ls-files", "-z").decode(errors="surrogateescape").split("\0") if p]


def scan(root, tracked, private):
    """(files read, failures as `path: rule`)."""
    read = 0
    failures = []
    for path in tracked:
        full = os.path.join(root, path)
        if platform_owned(path) or os.path.isdir(full):
            continue  # a directory entry is a submodule, not a file
        try:
            with open(full, "rb") as handle:
                content = handle.read().decode("utf-8", errors="replace")
        except FileNotFoundError:
            continue  # deleted in the working tree: the commit that ships removes it
        except OSError as err:
            raise GuardError(f"tracked {path} must read: {err.strerror}") from err
        read += 1
        rules = violations(path, content)
        if names_private_word(content, private):
            rules.append("private word (from the secret)")
        failures.extend(f"{path}: {rule}" for rule in rules)
    return read, failures


def main():
    try:
        root = repo_root()
        tracked = tracked_files(root)
        if SELF not in tracked:
            raise GuardError(f"git ls-files does not list {SELF}: the scan is not reading this tree")
        required = os.environ.get(PRIVATE_WORDS_REQUIRED_ENV) == "1"
        private = private_words_for_run(os.environ.get(PRIVATE_WORDS_ENV), required)
        if not private:
            print(f"public-tree guard: {PRIVATE_WORDS_ENV} is unset, private words not checked", file=sys.stderr)
        read, failures = scan(root, tracked, private)
    except GuardError as err:
        print(f"public-tree guard: {err}", file=sys.stderr)
        return 2
    print(f"public-tree guard read {read} of {len(tracked)} tracked files, {len(private)} private words")
    if read < MIN_TRACKED:
        print(f"public-tree guard: read only {read} tracked files; expected at least {MIN_TRACKED}", file=sys.stderr)
        return 2
    if failures:
        print("tracked files carry internal infrastructure (rule per file, value withheld):", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
