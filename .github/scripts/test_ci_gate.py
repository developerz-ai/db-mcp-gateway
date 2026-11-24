"""Pins ci.yml's gate: green only on success, or a skip `changes` ordered."""

import json
import os
import re
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ci_gate import SKIP_ONLY_WHEN, problems  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ci_gate.py")
CI_YML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "workflows", "ci.yml")
DOCS_ONLY = {
    "code": "false",
    "deps": "false",
    "image": "false",
    "msrv": "false",
    "website": "true",
    "deploy": "false",
}


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


def job_needs(workflow, job):
    """The `needs: [...]` list of `job` in ci.yml (stdlib only, no YAML parser)."""
    found = re.search(rf"^  {re.escape(job)}:\n(?:    .*\n)*?    needs: \[([^\]]*)\]", workflow, re.M)
    if not found:
        raise AssertionError(f"ci.yml has no `{job}` job with a one-line needs list")
    return [name.strip() for name in found.group(1).split(",")]


class Workflow(unittest.TestCase):
    """The table above is only half the contract: ci.yml must list the same jobs."""

    def setUp(self):
        with open(CI_YML, encoding="utf-8") as f:
            self.workflow = f.read()

    def test_gate_needs_exactly_the_table(self):
        self.assertEqual(sorted(job_needs(self.workflow, "gate")), sorted(SKIP_ONLY_WHEN))

    def test_merge_waits_on_every_gated_job(self):
        needs = job_needs(self.workflow, "merge")
        self.assertEqual(sorted(set(needs) - {"build", "gate"}), sorted(SKIP_ONLY_WHEN))

    def test_every_skip_output_is_emitted_by_changes(self):
        outputs = set(re.findall(r"^      (\w+): \$\{\{ steps\.diff\.outputs\.\1 \}\}$", self.workflow, re.M))
        self.assertEqual({o for o in SKIP_ONLY_WHEN.values() if o}, outputs)


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
