"""PreToolUse hook on Bash: refuses what CLAUDE.md's NEVER list and the release lane forbid.

    refused        -> exit 2, reason on stderr (Claude Code feeds it back to the agent)
    anything else  -> exit 0, silent

Fails open on anything it cannot parse: a seatbelt for honest mistakes, not a sandbox, and a
broken hook must never wedge a session. Text inside quotes and heredocs is removed first, so a
commit message that says "git push --force" is not a push; a quoted single word stays, so
`git push -f origin 'main'` still names main. DBMCP_HOOKS_OFF=1 in the session's environment turns
it off (.claude/README.md); as a prefix on the refused command it does nothing, because that never
reaches this process. Stdlib only.
"""

import json
import os
import re
import subprocess
import sys

WRAPPERS = {"sudo", "command", "exec", "env", "time", "nice"}
GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree"}
PROTECTED_BRANCH = re.compile(r"\A\+?(?:refs/heads/)?main\Z")
# `-o` takes a value, so an `f` after it is the value's.
FORCE_FLAG = re.compile(r"\A(?:-[a-np-zA-Z]*f|--force|--force-with-lease|--force-if-includes)")
RELEASE_TAG = re.compile(r"\A\+?(?:refs/tags/)?v\d+\.\d+\.\d+\S*\Z")
# `-m`, `-F`, `-C`, `-c`, `-t`, `-S`, `-u` take an attached value: the `n` in `-uno` is not -n's.
COMMIT_NO_VERIFY = re.compile(r"\A-[^mFCctSu-]*n")
TAG_MOVE_OR_DELETE = re.compile(r"\A(?:-(?![-mFu])[a-zA-Z]*[fd]|--force\Z|--delete\Z)")
QUOTED_WORD = re.compile(r"""(["'])(?!-)([\w./:+@-]*)\1""")
HEREDOC = re.compile(r"""<<-?\s*['"]?(\w+)['"]?.*?^\s*\1\s*$""", re.MULTILINE | re.DOTALL)
PKILL_SAFE_PATTERN = re.compile(r"""-\w*f\w*\s+['"]?\S*\[""")
IMAGE = "db-mcp-gateway"

NO_VERIFY = "--no-verify is forbidden (CLAUDE.md): fix the hook."


def refusal(command):
    for tokens in segments(command):
        reason = check(tokens, command)
        if reason:
            return reason
    return None


def segments(command):
    text = HEREDOC.sub(" ", command)
    text = QUOTED_WORD.sub(r"\2", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r"'[^']*'", "''", text)
    parts = re.split(r"&&|\|\||[;|\n]", text)
    return [tokens for tokens in (strip_prefix(part.split()) for part in parts) if tokens]


def strip_prefix(tokens):
    while tokens and (re.match(r"\A\w+=", tokens[0]) or tokens[0] in WRAPPERS):
        tokens = tokens[1:]
    return tokens


def check(tokens, command):
    name = os.path.basename(tokens[0])
    args = tokens[1:]
    if name == "git":
        return check_git(drop_git_options(args))
    if name == "gh":
        return check_gh(args)
    if name == "docker":
        return check_docker(args)
    if name == "pkill":
        return check_pkill(args, command)
    return None


def drop_git_options(args):
    while args and args[0].startswith("-"):
        args = args[2:] if args[0] in GIT_VALUE_OPTIONS else args[1:]
    return args


def check_git(args):
    if not args:
        return None
    sub, rest = args[0], args[1:]
    if sub == "commit" and any(a == "--no-verify" or COMMIT_NO_VERIFY.match(a) for a in rest):
        return NO_VERIFY
    if sub == "push":
        return check_push(rest)
    if sub == "worktree" and rest[:1] == ["add"]:
        return "No git worktrees (CLAUDE.md): split agents by file set in this one checkout."
    if sub == "tag":
        return check_tag(rest)
    return None


def check_push(args):
    if "--no-verify" in args:
        return NO_VERIFY
    refspecs = [a for a in args if not a.startswith("-")][1:]
    forced = any(FORCE_FLAG.match(a) or a.startswith("+") for a in args)
    deleting = "--delete" in args or "-d" in args
    if any(RELEASE_TAG.match(ref.split(":")[-1]) for ref in refspecs) and (forced or deleting):
        return "A published v* tag is never moved or deleted (.dz/briefs/release-due.md): ship the fix as the next patch."
    if any(ref.startswith(":") and RELEASE_TAG.match(ref[1:]) for ref in refspecs):
        return "A published v* tag is never deleted (.dz/briefs/release-due.md): ship the fix as the next patch."
    if forced and targets_main(refspecs):
        return "Force-push to main is forbidden (CLAUDE.md)."
    return None


def targets_main(refspecs):
    if not refspecs or any(ref.lstrip("+") == "HEAD" for ref in refspecs):
        return current_branch() == "main"
    return any(PROTECTED_BRANCH.match(ref.split(":")[-1]) for ref in refspecs)


def current_branch():
    try:
        out = subprocess.run(
            ["git", "symbolic-ref", "--short", "-q", "HEAD"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip()


def check_tag(args):
    moves = any(TAG_MOVE_OR_DELETE.match(a) for a in args)
    if moves and any(RELEASE_TAG.match(a) for a in args):
        return "A published v* tag is never moved or deleted (.dz/briefs/release-due.md): ship the fix as the next patch."
    return None


def check_gh(args):
    if args[:2] == ["pr", "merge"] and "--admin" in args:
        return "--admin bypasses the main-protection ruleset: get the required checks green."
    if args[:2] == ["release", "delete"]:
        return "Deleting a GitHub Release is a maintainer's recovery step, never an agent's (.dz/briefs/health.md)."
    return None


def check_docker(args):
    pushes = args[:1] == ["push"] or (args[:1] == ["buildx"] and "--push" in args)
    if pushes and any(IMAGE in a for a in args):
        return "The image is published by release.yml and ci.yml only, never pushed by hand."
    return None


def check_pkill(args, command):
    if any(re.match(r"\A-\w*f\w*\Z", a) for a in args) and not PKILL_SAFE_PATTERN.search(command):
        return "pkill -f matches this very shell, whose command line holds the pattern: use a [b]racket pattern, or kill by pid."
    return None


def main():
    if os.environ.get("DBMCP_HOOKS_OFF") == "1":
        return 0
    try:
        command = json.load(sys.stdin).get("tool_input", {}).get("command")
        reason = refusal(command) if isinstance(command, str) else None
    except Exception:  # noqa: BLE001 -- fail open: a broken hook must never wedge a session
        reason = None
    if reason:
        print(f"Refused by .claude/hooks/guard_bash.py: {reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
