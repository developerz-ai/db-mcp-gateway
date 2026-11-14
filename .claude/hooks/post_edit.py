"""PostToolUse hook on Edit|Write|MultiEdit: the repo rules an edit most often trips, caught at the
edit instead of at bin/ci or in review.

    rustfmt diff in the edited .rs -> exit 2, the diff on stderr
    everything else                -> exit 0, advice as additionalContext

Check-only: a rewrite would change the file under the agent and fail its next Edit. A missing tool
or a timeout is the environment, never the agent's fault, so it only ever says so. The edit has
already happened, so this hook cannot block anything. DBMCP_HOOKS_OFF=1 turns it off. Stdlib only.
"""

import json
import os
import shutil
import subprocess
import sys

TOOL_SECONDS = 20
MAX_LOC = 300
SECURITY_PATHS = (
    "src/auth/", "src/authz/", "src/audit/", "src/exec/", "src/tools/", "src/state/",
    "src/config/secret.rs", "src/config/secret/",
)
SPEC_PATHS = ("src/tools/", "src/config/", "src/transport/")
MIGRATION_DIRS = ("migrations/", "migrations-mysql/")


def relative(file_path, root):
    absolute = os.path.realpath(os.path.join(root, file_path))
    if absolute.startswith(root + os.sep) and os.path.isfile(absolute):
        return os.path.relpath(absolute, root)
    return None


def run(*command):
    """(combined output, exit code), or (None, None) when the tool is absent or timed out."""
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=TOOL_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, None
    return done.stdout + done.stderr, done.returncode


def rustfmt_diff(path, root):
    if not path.endswith(".rs") or not shutil.which("rustfmt"):
        return None
    full = os.path.join(root, path)
    out, code = run("rustfmt", "--check", "--color", "never", full)
    # Exit 1 is also a parse error mid-edit, and rustfmt walks into child modules: only a diff in
    # the edited file itself is this edit's finding.
    if code == 1 and out and f"Diff in {full}:" in out:
        return out
    return None


def advice(path, root):
    notes = [
        security_note(path),
        spec_note(path),
        migration_note(path, root),
        size_note(path, root),
        version_note(path),
        brief_note(path),
        lint_note(path, root),
    ]
    return [note for note in notes if note]


def security_note(path):
    if path.startswith(SECURITY_PATHS):
        return (
            f"{path} is a security-review path (CLAUDE.md): the PR carries the `security review required` "
            "label and is merged by a human. Check: no credential in errors/logs/responses, an audit row on "
            "every outcome, no authz bypass via constraint merge, no timeout or row-cap bypass."
        )
    return None


def spec_note(path):
    if path.startswith(SPEC_PATHS) and path.endswith(".rs"):
        return (
            "A behaviour change here (tool surface, error code, config key) updates "
            "website/docs/initial-idea/ in the same PR."
        )
    return None


def migration_note(path, root):
    if not path.startswith(MIGRATION_DIRS):
        return None
    _, code = run("git", "-C", root, "ls-files", "--error-unmatch", path)
    if code == 0:
        return (
            f"{path} is a committed migration: never edit one that has been applied (its checksum changes and "
            "the migrator refuses to boot). Add the next numbered file instead (.claude/skills/state-migrations)."
        )
    return None


def size_note(path, root):
    if not (path.startswith("src/") and path.endswith(".rs")):
        return None
    with open(os.path.join(root, path), encoding="utf-8", errors="replace") as source:
        lines = sum(1 for _ in source)
    if lines > MAX_LOC:
        return f"{path} is {lines} lines; CLAUDE.md caps files at {MAX_LOC} LOC. Split by responsibility."
    return None


def version_note(path):
    if path == "Cargo.toml":
        return (
            "If this moves `version`: that is the release PR, alone, titled `chore(release): <next>` with "
            "Cargo.lock and README.md; the v* tag goes on the merge commit after it lands (.dz/briefs/release-due.md)."
        )
    return None


def brief_note(path):
    if path == ".dz/briefs/health.md":
        return "tests/brief_rows.rs pins this brief's signal table against its ## Rows list: `cargo test --test brief_rows`."
    return None


def lint_note(path, root):
    if path.startswith(".github/workflows/"):
        return tool_note("actionlint", path)
    if path.startswith("bin/") and not os.path.splitext(path)[1] and shell_script(os.path.join(root, path)):
        return tool_note("shellcheck", "-S", "warning", path)
    return None


def shell_script(full_path):
    with open(full_path, encoding="utf-8", errors="replace") as source:
        first = source.readline()
    return first.startswith("#!") and ("bash" in first or first.rstrip().endswith("sh"))


def tool_note(tool, *args):
    if not shutil.which(tool):
        return f"{tool} is not on PATH, so {args[-1]} was not linted; CI and review will."
    out, code = run(tool, *args)
    if code is None:
        return f"{tool} timed out on {args[-1]}; it was not linted."
    if code != 0:
        return f"{tool} on {args[-1]}:\n" + "".join((out or "").splitlines(keepends=True)[:40])
    return None


def main():
    if os.environ.get("DBMCP_HOOKS_OFF") == "1":
        return 0
    try:
        file_path = json.load(sys.stdin).get("tool_input", {}).get("file_path")
        root = os.path.realpath(os.getcwd())
        path = relative(file_path, root) if isinstance(file_path, str) else None
        if not path:
            return 0
        diff = rustfmt_diff(path, root)
        if diff:
            print("rustfmt --check:\n" + "".join(diff.splitlines(keepends=True)[:40]), file=sys.stderr)
            return 2
        notes = advice(path, root)
        if notes:
            output = {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "\n".join(notes)}}
            print(json.dumps(output))
    except Exception as err:  # noqa: BLE001 -- advice only: never fail the edit over the hook itself
        print(f"post_edit hook: {type(err).__name__}: {err}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
