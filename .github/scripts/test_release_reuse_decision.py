"""Pins release.yml's reuse decision: red CI blocks, absent CI builds, green reuses."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from release_reuse_decision import decide  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "release_reuse_decision.py")


def action(*args):
    return decide(*args)[0]


class Decide(unittest.TestCase):
    def test_red_ci_blocks(self):
        for conclusion in ("failure", "cancelled", "timed_out", "startup_failure", ""):
            for image in ("unchecked", "present", "missing"):
                self.assertEqual(action("completed", conclusion, image, True, True), "block")

    def test_no_run_waits_out_the_grace_then_builds(self):
        self.assertEqual(action("none", "", "unchecked", False, False), "wait")
        self.assertEqual(action("none", "", "unchecked", True, False), "build")

    def test_running_ci_waits_until_the_deadline_then_blocks(self):
        for status in ("queued", "in_progress", "waiting", "pending", "requested"):
            self.assertEqual(action(status, "", "unchecked", True, False), "wait")
            self.assertEqual(action(status, "", "unchecked", True, True), "block")

    def test_green_ci_probes_then_reuses_or_builds(self):
        self.assertEqual(action("completed", "success", "unchecked", True, False), "check-image")
        self.assertEqual(action("completed", "success", "present", True, False), "reuse")
        self.assertEqual(action("completed", "success", "missing", True, False), "build")

    def test_green_ci_is_reused_even_past_the_deadline(self):
        self.assertEqual(action("completed", "success", "present", True, True), "reuse")

    def test_unknown_image_state_is_rejected(self):
        with self.assertRaises(ValueError):
            decide("completed", "success", "yes", True, False)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-I", SCRIPT, *args], capture_output=True, text=True, check=False
        )

    def test_prints_action_then_reason(self):
        out = self.run_cli("completed", "failure", "unchecked", "1", "0")
        self.assertEqual(out.returncode, 0)
        self.assertTrue(out.stdout.startswith("block ci.yml concluded 'failure'"))

    def test_wrong_arity_is_a_usage_error(self):
        self.assertEqual(self.run_cli("completed").returncode, 2)


if __name__ == "__main__":
    unittest.main()
