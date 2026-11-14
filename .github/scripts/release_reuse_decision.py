"""Decide whether release.yml re-tags the image ci.yml tested for the tag's commit.

Pure function of what the `reuse` job has observed; the job's shell loop does
the polling and the registry probe, and acts on the one-line verdict printed
here (`<action> <reason>`). Pinned by test_release_reuse_decision.py.

Actions:
  wait         ci.yml has not finished (or not registered yet): poll again
  check-image  ci.yml is green: probe the registry for `sha-<7>`
  reuse        green and the image exists: re-tag it
  build        no ci.yml run for this commit, or green without an image:
               build from the tag, with a warning
  block        ci.yml failed/cancelled, or never finished: fail the release
"""

import sys

IMAGE_STATES = ("unchecked", "present", "missing")


def decide(status, conclusion, image, grace_over, deadline_over):
    if image not in IMAGE_STATES:
        raise ValueError(f"image must be one of {IMAGE_STATES}, got {image!r}")
    if status == "none":
        if grace_over:
            return "build", "no ci.yml push run on main for this commit"
        return "wait", "ci.yml run not registered yet"
    if status != "completed":
        if deadline_over:
            return "block", f"ci.yml still {status} after 40 min (re-run this job once it finishes)"
        return "wait", f"ci.yml is {status}"
    if conclusion != "success":
        return "block", f"ci.yml concluded '{conclusion}'; fix it and ship the next patch"
    if image == "unchecked":
        return "check-image", "ci.yml is green"
    if image == "present":
        return "reuse", "ci.yml is green and sha-<7> exists"
    return "build", "ci.yml is green but its sha-<7> image is missing"


def main(argv):
    if len(argv) != 6:
        print(
            "usage: release_reuse_decision.py STATUS CONCLUSION IMAGE GRACE_OVER(0|1) DEADLINE_OVER(0|1)",
            file=sys.stderr,
        )
        return 2
    status, conclusion, image, grace, deadline = argv[1:]
    action, reason = decide(status, conclusion, image, grace == "1", deadline == "1")
    print(f"{action} {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
