"""Proves every public_tree.py rule can fail, and that the public ones pass."""

import os
import sys
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


class Scan(unittest.TestCase):
    def test_reports_path_and_rule_never_the_value(self):
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            for name, body in (("ok.md", "public"), ("bad.md", "x QUIMTEL y"), (".dz/x.md", "QUIMTEL")):
                os.makedirs(os.path.dirname(os.path.join(root, name)), exist_ok=True)
                with open(os.path.join(root, name), "w") as handle:
                    handle.write(body)
            read, failures = scan(root, ["ok.md", "bad.md", ".dz/x.md"], private_words("quimtel"))
        self.assertEqual(read, 2)
        self.assertEqual(failures, ["bad.md: private word (from the secret)"])
        self.assertNotIn("quimtel", "".join(failures).lower())

    def test_a_file_deleted_in_the_working_tree_is_skipped(self):
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(scan(root, ["deleted.md"], []), (0, []))

    def test_an_unreadable_tracked_file_fails_closed(self):
        import tempfile

        with tempfile.TemporaryDirectory() as root, self.assertRaises(GuardError):
            os.symlink("loop", os.path.join(root, "loop"))
            scan(root, ["loop"], [])


if __name__ == "__main__":
    unittest.main()
