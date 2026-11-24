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
the file and the rule, never the matched text: CI logs are public. A tracked
path is scanned too, and a reported path has every private or forbidden word
masked (or is withheld whole when a host, repository or home path is left).

Git is the oracle for "tracked", after checking that git answers for this
checkout and not for an outer repository. The scan reads each tracked blob from
git's index, never the working tree: a symlink is scanned as its target text
and never followed, a file deleted but not yet staged is still scanned (the
index is what the next commit ships), and an entry git cannot hand back fails
the scan closed. `.dz/` is excluded: the platform's setup template rewrites it
whole. `.mcp.json` is scanned on purpose.

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

OWN_DOMAIN = ".developerz.ai"
# A run of hostname characters. One flat class: linear on any input, where a
# nested `(?:label\.)+domain` pattern backtracks quadratically on a long
# dotted name that never reaches the domain.
HOSTNAME_RUN = re.compile(r"[a-z0-9.-]+", re.IGNORECASE | re.ASCII)
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


def _names_internal_host(content):
    """Whether any `<labels>.developerz.ai` other than a public host appears.
    Finds the fixed domain suffix inside each hostname run first, then reads the
    labels before it once: linear in the content."""
    for run in HOSTNAME_RUN.finditer(content):
        text = run.group(0).lower()
        labels_start = len(text) - len(text.lstrip(".-"))
        at = text.find(OWN_DOMAIN)
        while at != -1:
            end = at + len(OWN_DOMAIN)
            ends_on_boundary = end == len(text) or not text[end].isalnum()
            has_labels = at > labels_start
            if ends_on_boundary and has_labels and not _is_public_host(text, labels_start, end):
                return True
            at = text.find(OWN_DOMAIN, at + 1)
    return False


def _is_public_host(text, start, end):
    # Length first: never slice a long run once per suffix it contains.
    return any(len(host) == end - start and text[start:end] == host for host in PUBLIC_HOSTS)


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
    if _names_internal_host(content):
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


# Index modes: a gitlink (submodule) has no blob in this repository.
GITLINK_MODE = "160000"


def tracked_entries(root):
    """(path, blob id) per index entry, gitlinks dropped. Every conflict stage
    of a path is its own entry: each is content the tree may ship."""
    entries = []
    for record in _git(root, "ls-files", "-s", "-z").decode(errors="surrogateescape").split("\0"):
        if not record:
            continue
        meta, _, path = record.partition("\t")
        mode, blob, _stage = meta.split(" ")
        if mode != GITLINK_MODE:
            entries.append((path, blob))
    return entries


def iter_blobs(root, blobs):
    """(blob id, bytes) per unique id, streamed from one `git cat-file --batch`:
    each id is asked for only after the previous blob was handed on, so peak
    memory is the largest blob, not the tree. A missing or non-blob object is a
    GuardError: the scan never passes what it did not read."""
    try:
        proc = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as err:
        raise GuardError(f"git cat-file must run: {err}") from err
    try:
        for blob in dict.fromkeys(blobs):
            yield blob, _next_blob(proc, blob)
    finally:
        proc.kill()
        proc.wait()
        proc.stdin.close()
        proc.stdout.close()


def _next_blob(proc, blob):
    try:
        proc.stdin.write(f"{blob}\n".encode())
        proc.stdin.flush()
    except OSError as err:
        raise GuardError(f"git cat-file stopped reading: {err}") from err
    header = proc.stdout.readline().decode(errors="replace").split(" ")
    if len(header) != 3 or header[0] != blob or header[1] != "blob" or not header[2].strip().isdigit():
        raise GuardError(f"tracked blob {blob} must read from the index")
    size = int(header[2])
    content = proc.stdout.read(size)
    if len(content) != size or proc.stdout.read(1) != b"\n":
        raise GuardError(f"tracked blob {blob} came back truncated")
    return content


def path_violations(path, private):
    """The rules a tracked path's own name breaks: a name is as public as a blob."""
    rules = [f"{rule} in the file name" for rule in violations("", path)]
    if names_private_word(path, private):
        rules.append("private word (from the secret) in the file name")
    return rules


WITHHELD_PATH = "<path withheld: its name breaks a rule>"


def shown_path(path, private):
    """`path` as a public log may print it: every private or forbidden word
    masked, and the whole name withheld when what is left still breaks a rule
    (a host, repository or home path has no single word to mask)."""
    shown = path
    for word in (*private, *(word for _, word in FORBIDDEN_WORDS)):
        shown = word.sub("<redacted>", shown)
    return WITHHELD_PATH if path_violations(shown, private) else shown


def scan(root, entries, private):
    """(blobs read, failures as `path: rule`) over index entries (path, blob)."""
    entries = [(path, blob) for path, blob in entries if not platform_owned(path)]
    paths_by_blob = {}
    for path, blob in entries:
        paths_by_blob.setdefault(blob, []).append(path)
    rules_by_entry = {}
    for blob, data in iter_blobs(root, paths_by_blob):
        content = data.decode("utf-8", errors="replace")
        private_hit = names_private_word(content, private)
        for path in paths_by_blob[blob]:
            rules = violations(path, content)
            if private_hit:
                rules.append("private word (from the secret)")
            rules.extend(path_violations(path, private))
            rules_by_entry[path, blob] = rules
    failures = [
        f"{shown_path(path, private)}: {rule}"
        for path, blob in entries
        for rule in rules_by_entry[path, blob]
    ]
    return len(entries), failures


def main():
    try:
        root = repo_root()
        entries = tracked_entries(root)
        if SELF not in {path for path, _ in entries}:
            raise GuardError(f"git ls-files does not list {SELF}: the scan is not reading this tree")
        required = os.environ.get(PRIVATE_WORDS_REQUIRED_ENV) == "1"
        private = private_words_for_run(os.environ.get(PRIVATE_WORDS_ENV), required)
        if not private:
            print(f"public-tree guard: {PRIVATE_WORDS_ENV} is unset, private words not checked", file=sys.stderr)
        read, failures = scan(root, entries, private)
    except GuardError as err:
        print(f"public-tree guard: {err}", file=sys.stderr)
        return 2
    print(f"public-tree guard read {read} of {len(entries)} tracked files, {len(private)} private words")
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
