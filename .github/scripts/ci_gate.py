"""ci.yml's `gate` verdict: the one check the ruleset requires.

GitHub counts a skipped required job as passed, so requiring each job let a
failed `changes` (or a skipped dependency) merge a PR that ran nothing. `gate`
runs `if: always()` and reads every quality job's result from `toJSON(needs)`
in the NEEDS environment variable. A job passes when it succeeded, or when it
was skipped because `changes` succeeded and said its path filter matched
nothing. Anything else (failure, cancelled, a skip `changes` did not order, a
job missing from `needs` or one this table does not know) fails the gate.

Pinned by test_ci_gate.py.
"""

import json
import os
import sys

# Every job `gate` needs, with the `changes` output whose `false` lets it skip;
# None means it must succeed on every run.
SKIP_ONLY_WHEN = {
    "changes": None,
    "fmt": None,
    "clippy": "code",
    "test": "code",
    "yugabyte": "code",
    "audit": "deps",
    "image-check": "image",
    "msrv": "msrv",
    "website": "website",
    "secret-scan": None,
    "scripts": None,
    "public-tree": None,
}


def problems(needs):
    """Every reason the gate fails, one line per job; empty means green."""
    found = [f"{job}: missing from gate.needs" for job in SKIP_ONLY_WHEN if job not in needs]
    found += [f"{job}: not in ci_gate.py's table" for job in needs if job not in SKIP_ONLY_WHEN]
    changes = needs.get("changes", {})
    filters = (changes.get("outputs") or {}) if changes.get("result") == "success" else {}
    for job, output in SKIP_ONLY_WHEN.items():
        if job not in needs:
            continue
        result = needs[job].get("result", "")
        if result == "success":
            continue
        if result == "skipped" and output is not None and filters.get(output) == "false":
            continue
        found.append(f"{job}: {result or 'no result'}")
    return found


def main():
    try:
        needs = json.loads(os.environ["NEEDS"])
    except (KeyError, json.JSONDecodeError) as err:
        print(f"gate: NEEDS must hold toJSON(needs): {err}", file=sys.stderr)
        return 2
    found = problems(needs)
    for line in found:
        print(f"::error::{line}")
    if found:
        return 1
    print(f"gate: {len(needs)} jobs passed or were skipped by `changes`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
