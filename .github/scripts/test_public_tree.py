"""Proves every public_tree.py rule can fail, and that the public ones pass."""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from public_tree import (  # noqa: E402
    GuardError,
    names_private_word,
    platform_owned,
    private_words,
    private_words_for_run,
    scan,
    tracked_entries,
    violations,
)

MARKER_RULE = "agent or skill file without this repository's marker"


class Rules(unittest.TestCase):
    def test_passes_public_references(self):
        content = (
            "See https://www.developerz.ai, email security@developerz.ai, "
            "pull ghcr.io/developerz-ai/db-mcp-gateway, clone "
            "developerz-ai/db-mcp-gateway.git, cache under ~/.cargo/registry."
        )
        self.assertEqual(violations("README.md", content), [])

    def test_skips_only_platform_owned_paths(self):
        self.assertTrue(platform_owned(".dz/maintainer/maintainer.yml"))
        for path in (".mcp.json", ".mcp.json.bak", "config/.mcp.json", ".dzz/x", "README.md"):
            self.assertFalse(platform_owned(path), f"{path} must be scanned")

    def test_fires_on_internal_host(self):
        host = ".".join(["svc", "developerz", "ai"])
        self.assertEqual(
            violations("a.md", f"url: https://{host}/v1"), ["internal host on our own domain"]
        )

    def test_host_rule_edges(self):
        domain = ".".join(["developerz", "ai"])
        for text in (f"www.{domain}.", f"https://www.{domain}/x", f"apex {domain} only", f"a.{domain}x"):
            self.assertEqual(violations("a.md", text), [], text)
        for text in (f"WWW.{domain}.{domain}", f"..svc.{domain}", f"svc.{domain}-x", f"a.b.{domain}"):
            self.assertEqual(violations("a.md", text), ["internal host on our own domain"], text)

    def test_host_rule_is_linear_on_long_dotted_names(self):
        domain = ".".join(["developerz", "ai"])
        for content in ("a." * 200_000, "a." * 200_000 + domain + "x", f"www.{domain}" * 50_000):
            started = time.monotonic()
            violations("a.md", content)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_fires_on_the_setup_mode_name(self):
        word = "-".join(["DZ", "RUNNER"])
        self.assertEqual(violations("a.md", f"x {word} y"), ["setup-mode name"])

    def test_fires_on_a_private_word_from_the_secret(self):
        words = private_words(" Quimtel ,\n\nzorblax.io\n")
        self.assertEqual(len(words), 2)
        self.assertTrue(names_private_word("x QUIMTEL y", words))
        self.assertTrue(names_private_word("see zorblax.io.", words))
        self.assertFalse(names_private_word("zorblax-io and quim", words))
        self.assertEqual(private_words(None), [])
        self.assertEqual(private_words(" , \n "), [])

    def test_a_required_run_without_the_secret_fails(self):
        with self.assertRaises(GuardError):
            private_words_for_run(None, True)
        with self.assertRaises(GuardError):
            private_words_for_run(" , \n", True)
        self.assertEqual(private_words_for_run(None, False), [])
        self.assertEqual(len(private_words_for_run("quimtel", True)), 1)

    def test_fires_on_our_own_mcp_service_in_the_tracked_config(self):
        host = ".".join(["mcp", "developerz", "ai"])
        config = '{"mcpServers":{"x":{"type":"http","url":"https://%s/v1/mcp"}}}' % host
        self.assertFalse(platform_owned(".mcp.json"))
        self.assertEqual(violations(".mcp.json", config), ["internal host on our own domain"])

    def test_fires_on_private_repository(self):
        for owner, repo in (("developerz-ai", "infra"), ("Developerz-AI", "Infra")):
            self.assertEqual(
                violations("a.md", f"see `{owner}/{repo}`."), ["private repository"]
            )
        self.assertEqual(violations("a.md", "/".join(["Developerz-AI", "DB-MCP-Gateway"])), [])

    def test_fires_on_home_directory(self):
        path = "/".join(["", "home", "someone", "src"])
        self.assertEqual(violations("a.md", f"cd {path}"), ["home directory path"])
        self.assertEqual(violations("a.md", f"line one\n{path}"), ["home directory path"])

    def test_fires_on_agent_file_without_marker(self):
        self.assertEqual(violations(".claude/agents/x.md", "> Specialist definition."), [MARKER_RULE])
        self.assertEqual(violations(".claude/skills/x/SKILL.md", "> House skill."), [MARKER_RULE])
        self.assertEqual(violations(".claude/commands/x.md", "no marker needed"), [])


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def temp_dir(case):
    path = tempfile.mkdtemp()
    case.addCleanup(shutil.rmtree, path)
    return path


def repo_with(case, files):
    """A real git repository whose index holds `files` (path -> body)."""
    root = temp_dir(case)
    git(root, "init", "-q")
    for name, body in files.items():
        full = os.path.join(root, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as handle:
            handle.write(body)
    git(root, "add", "-A")
    return root


class Scan(unittest.TestCase):
    def test_reports_path_and_rule_never_the_value(self):
        root = repo_with(self, {"ok.md": "public", "bad.md": "x QUIMTEL y", ".dz/x.md": "QUIMTEL"})
        read, failures = scan(root, tracked_entries(root), private_words("quimtel"))
        self.assertEqual(read, 2)
        self.assertEqual(failures, ["bad.md: private word (from the secret)"])
        self.assertNotIn("quimtel", "".join(failures).lower())

    def test_an_unstaged_deletion_still_scans_the_indexed_blob(self):
        root = repo_with(self, {"gone.md": "x QUIMTEL y"})
        os.remove(os.path.join(root, "gone.md"))
        self.assertEqual(
            scan(root, tracked_entries(root), private_words("quimtel")),
            (1, ["gone.md: private word (from the secret)"]),
        )

    def test_reads_the_index_not_the_working_tree(self):
        root = repo_with(self, {"a.md": "x QUIMTEL y"})
        with open(os.path.join(root, "a.md"), "w") as handle:
            handle.write("clean now, but not staged")
        _, failures = scan(root, tracked_entries(root), private_words("quimtel"))
        self.assertEqual(failures, ["a.md: private word (from the secret)"])

    def test_a_symlink_is_scanned_as_its_target_text_never_followed(self):
        root = repo_with(self, {})
        outside = temp_dir(self)
        with open(os.path.join(outside, "x"), "w") as handle:
            handle.write("QUIMTEL in the followed file")
        os.symlink(os.path.join(outside, "QUIMTEL-target"), os.path.join(root, "named"))
        os.symlink(os.path.join(outside, "x"), os.path.join(root, "followed"))
        os.symlink("loop", os.path.join(root, "loop"))
        git(root, "add", "-A")
        _, failures = scan(root, tracked_entries(root), private_words("quimtel"))
        self.assertEqual(failures, ["named: private word (from the secret)"])

    def test_an_unreadable_index_entry_fails_closed(self):
        root = repo_with(self, {"a.md": "public"})
        missing = "0123456789abcdef0123456789abcdef01234567"
        with self.assertRaises(GuardError):
            scan(root, [("a.md", missing)], [])


if __name__ == "__main__":
    unittest.main()
