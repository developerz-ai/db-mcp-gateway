"""Tests for the Claude Code hooks. Stdlib only: `python3 -I .claude/hooks/test_hooks.py`."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load("guard_bash")
post_edit = load("post_edit")

REFUSED = [
    "git commit --no-verify -m x",
    "git commit -nm x",
    "git push --force origin main",
    "git push -f origin main",
    "git push -f origin HEAD:main",
    "git push origin +main",
    "git push --no-verify origin feat/x",
    "git worktree add ../x",
    "git tag -d v1.2.3",
    "git tag -fa v2.0.3 -m x",
    "git push --delete origin v2.0.3",
    "git push origin :refs/tags/v2.0.3",
    "git push -f origin v2.0.3",
    "gh pr merge 12 --squash --admin",
    "gh release delete v2.0.3 --yes",
    "docker push ghcr.io/developerz-ai/db-mcp-gateway:2.1.0",
    "docker buildx build --push -t ghcr.io/developerz-ai/db-mcp-gateway:x .",
    "pkill -f cargo",
    "cd /x && git push --force origin main",
    "env FOO=1 git -C . push -f origin main",
]

ALLOWED = [
    "git tag -a v9.9.9 -m x",
    "git push origin v9.9.9",
    "git tag -a v2.1.0 -m \"v2.1.0\" abc123",
    "git commit -m \"fix: say git push --force main in msg\"",
    "git commit -um x",
    "git push -u origin feat/x",
    "git push --force-with-lease origin feat/x",
    "git worktree list",
    "git tag -l",
    "git tag",
    "gh pr merge 12 --squash",
    "gh release view v2.0.3",
    "docker build -t db-mcp-gateway:dev .",
    "pkill -f '[c]argo test'",
    "cargo test --test public_tree",
    "bin/ci",
    "echo \"git worktree add\" | cat",
]


def run_hook(script, payload, env=None):
    return subprocess.run(
        [sys.executable, "-I", os.path.join(HERE, script)],
        input=payload, capture_output=True, text=True, env=env, check=False,
    )


class GuardBashTest(unittest.TestCase):
    def test_refuses(self):
        for command in REFUSED:
            with self.subTest(command=command):
                self.assertIsNotNone(guard.refusal(command))

    def test_allows(self):
        for command in ALLOWED:
            with self.subTest(command=command):
                self.assertIsNone(guard.refusal(command))

    def test_refusal_exits_2_with_reason(self):
        done = run_hook("guard_bash.py", json.dumps({"tool_input": {"command": "git push -f origin main"}}))
        self.assertEqual(done.returncode, 2)
        self.assertIn("Force-push to main", done.stderr)

    def test_fails_open_on_bad_input(self):
        self.assertEqual(run_hook("guard_bash.py", "{bad json").returncode, 0)

    def test_off_switch(self):
        env = dict(os.environ, DBMCP_HOOKS_OFF="1")
        payload = json.dumps({"tool_input": {"command": "git push -f origin main"}})
        self.assertEqual(run_hook("guard_bash.py", payload, env).returncode, 0)


class PostEditTest(unittest.TestCase):
    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())

    def write(self, path, lines):
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as out:
            out.write("// x\n" * lines)

    def test_security_path_note(self):
        self.assertIn("security review required", post_edit.security_note("src/authz/mod.rs"))
        self.assertIsNone(post_edit.security_note("src/transport/mod.rs"))

    def test_spec_note(self):
        self.assertIsNotNone(post_edit.spec_note("src/tools/run_query.rs"))
        self.assertIsNone(post_edit.spec_note("src/audit/mod.rs"))

    def test_size_note(self):
        self.write("src/big.rs", post_edit.MAX_LOC + 1)
        self.write("src/small.rs", 10)
        self.assertIn("300 LOC", post_edit.size_note("src/big.rs", self.root))
        self.assertIsNone(post_edit.size_note("src/small.rs", self.root))

    def test_release_and_brief_notes(self):
        self.assertIn("chore(release)", post_edit.version_note("Cargo.toml"))
        self.assertIn("brief_rows", post_edit.brief_note(".dz/briefs/health.md"))
        self.assertIsNone(post_edit.version_note("README.md"))

    def test_committed_migration_note(self):
        self.write("migrations/0001_x.sql", 1)
        self.write("migrations/0002_new.sql", 1)
        subprocess.run(["git", "init", "-q", self.root], check=True)
        subprocess.run(["git", "-C", self.root, "add", "migrations/0001_x.sql"], check=True)
        self.assertIn("committed migration", post_edit.migration_note("migrations/0001_x.sql", self.root))
        self.assertIsNone(post_edit.migration_note("migrations/0002_new.sql", self.root))

    def test_outside_root_is_ignored(self):
        self.assertIsNone(post_edit.relative("/etc/passwd", self.root))
        self.assertIsNone(post_edit.relative("missing.rs", self.root))

    def test_never_fails_the_edit(self):
        self.assertEqual(run_hook("post_edit.py", "{bad json").returncode, 0)
        payload = json.dumps({"tool_input": {"file_path": "/etc/passwd"}})
        self.assertEqual(run_hook("post_edit.py", payload).returncode, 0)


if __name__ == "__main__":
    unittest.main()
