"""Pins ci.yml's gate: green only on success, or a skip `changes` ordered."""

import json
import os
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ci_gate import SKIP_ONLY_WHEN, problems  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ci_gate.py")
DOCS_ONLY = {"code": "false", "deps": "false", "image": "false", "msrv": "false", "website": "true"}


def run(changes_result="success", outputs=None, **results):
    needs = {job: {"result": "success", "outputs": {}} for job in SKIP_ONLY_WHEN}
    needs["changes"] = {"result": changes_result, "outputs": outputs or {}}
    for job, result in results.items():
        needs[job.replace("_", "-")] = {"result": result, "outputs": {}}
    return needs


SKIPPABLE = [job for job, output in SKIP_ONLY_WHEN.items() if output]


class Gate(unittest.TestCase):
    def test_all_green_passes(self):
        self.assertEqual(problems(run()), [])

    def test_docs_only_skips_pass(self):
        skipped = {job: "skipped" for job in SKIPPABLE if job != "website"}
        needs = run(outputs=DOCS_ONLY)
        for job in skipped:
            needs[job]["result"] = "skipped"
        self.assertEqual(problems(needs), [])

    def test_a_failed_changes_fails_even_when_everything_skipped(self):
        needs = run(changes_result="failure")
        for job in SKIPPABLE:
            needs[job]["result"] = "skipped"
        found = problems(needs)
        self.assertIn("changes: failure", found)
        for job in SKIPPABLE:
            self.assertIn(f"{job}: skipped", found)

    def test_outputs_of_a_failed_changes_are_ignored(self):
        # `changes` can write `code=false` and fail afterwards.
        needs = run(changes_result="failure", outputs=DOCS_ONLY)
        needs["test"]["result"] = "skipped"
        self.assertEqual(problems(needs), ["changes: failure", "test: skipped"])

    def test_a_skip_changes_did_not_order_fails(self):
        needs = run(outputs={"code": "true", "deps": "false"})
        needs["test"]["result"] = "skipped"
        needs["audit"]["result"] = "skipped"
        self.assertEqual(problems(needs), ["test: skipped"])

    def test_empty_filter_output_is_not_false(self):
        needs = run(outputs={})
        needs["clippy"]["result"] = "skipped"
        self.assertEqual(problems(needs), ["clippy: skipped"])

    def test_unskippable_jobs_must_succeed(self):
        for job in ("fmt", "secret-scan", "scripts", "public-tree"):
            needs = run(outputs=DOCS_ONLY)
            needs[job]["result"] = "skipped"
            self.assertEqual(problems(needs), [f"{job}: skipped"])

    def test_failure_and_cancelled_fail(self):
        for result in ("failure", "cancelled", ""):
            needs = run()
            needs["yugabyte"]["result"] = result
            self.assertEqual(len(problems(needs)), 1)

    def test_needs_and_table_stay_in_step(self):
        needs = run()
        del needs["msrv"]
        needs["new-job"] = {"result": "success"}
        self.assertEqual(
            problems(needs), ["msrv: missing from gate.needs", "new-job: not in ci_gate.py's table"]
        )


class Cli(unittest.TestCase):
    def invoke(self, env):
        return subprocess.run(
            [sys.executable, "-I", SCRIPT], env=env, capture_output=True, text=True, check=False
        )

    def test_exit_codes(self):
        self.assertEqual(self.invoke({"NEEDS": json.dumps(run())}).returncode, 0)
        red = self.invoke({"NEEDS": json.dumps(run(changes_result="failure"))})
        self.assertEqual(red.returncode, 1)
        self.assertIn("::error::changes: failure", red.stdout)
        self.assertEqual(self.invoke({}).returncode, 2)
        self.assertEqual(self.invoke({"NEEDS": "not json"}).returncode, 2)


if __name__ == "__main__":
    unittest.main()
