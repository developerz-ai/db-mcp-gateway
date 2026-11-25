"""Pins publish_chart.sh (stubbed docker) and release.yml's chart job."""

import os
import re
import subprocess
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(HERE, "publish_chart.sh")
DIGEST = "sha256:" + "ab" * 32
HELM_PIN = re.compile(r"^HELM=(alpine/helm:\S+@sha256:[0-9a-f]{64})$", re.M)

# `package` writes a chart archive into the mounted /out; `push` stores the
# archive in $STORE and reports a digest; `pull` serves it back.
DOCKER = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CALLS"
version=${VERSION_IN_USE:-}
for arg in "$@"; do
  case $arg in
    *:/out) out=${arg%:/out} ;;
    *:/work) work=${arg%:/work} ;;
  esac
done
case " $* " in
  *" package "*)
    mkdir -p "$TMP_CHART/db-mcp-gateway"
    echo "version: $version" > "$TMP_CHART/db-mcp-gateway/Chart.yaml"
    tar -czf "$out/db-mcp-gateway-$version.tgz" -C "$TMP_CHART" db-mcp-gateway ;;
  *" pull "*)
    [[ -z ${PULL_ERROR:-} ]] || { printf '%s\n' "$PULL_ERROR" >&2; exit 1; }
    [[ -f $STORE/chart.tgz ]] || { echo "Error: ghcr.io/o/charts/db-mcp-gateway:$version: not found" >&2; exit 1; }
    cp "$STORE/chart.tgz" "$work/published/db-mcp-gateway-$version.tgz"
    echo "Digest: $DIGEST" ;;
  *" push "*)
    [[ -z ${PUSH_FAILS:-} ]] || { echo 'Error: denied' >&2; exit 1; }
    cp "$work/db-mcp-gateway-$version.tgz" "$STORE/chart.tgz"
    [[ -n ${NO_DIGEST:-} ]] || echo "Digest: $DIGEST" ;;
esac
"""


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


class PublishChart(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        for name in ("tools", "store", "chart"):
            os.mkdir(os.path.join(self.tmp, name))
        docker = os.path.join(self.tmp, "tools", "docker")
        with open(docker, "w", encoding="utf-8") as f:
            f.write(DOCKER)
        os.chmod(docker, 0o755)

    def publish(self, version="2.7.0", epoch="1763000000", **env):
        base = {
            "PATH": os.path.join(self.tmp, "tools") + os.pathsep + os.environ["PATH"],
            "HOME": self.tmp,
            "CALLS": os.path.join(self.tmp, "calls"),
            "STORE": os.path.join(self.tmp, "store"),
            "TMP_CHART": os.path.join(self.tmp, "chart"),
            "VERSION_IN_USE": version,
            "DIGEST": DIGEST,
            "SOURCE_DATE_EPOCH": epoch,
        }
        return subprocess.run(
            [SCRIPT, version, "ghcr.io/o/charts"], env={**base, **env},
            capture_output=True, text=True, check=False,
        )

    def calls(self):
        with open(os.path.join(self.tmp, "calls"), encoding="utf-8") as f:
            return f.read().splitlines()

    def test_prints_only_the_digest_and_stamps_the_release_version(self):
        run = self.publish()
        self.assertEqual((run.returncode, run.stdout), (0, DIGEST + "\n"), run.stderr)
        package, pull, push = self.calls()
        self.assertIn("package /deploy/helm/db-mcp-gateway --version 2.7.0 --app-version 2.7.0", package)
        self.assertIn("--network=none", package)
        self.assertIn("pull oci://ghcr.io/o/charts/db-mcp-gateway --version 2.7.0", pull)
        self.assertIn("push /work/db-mcp-gateway-2.7.0.tgz oci://ghcr.io/o/charts", push)
        for call in (package, pull, push):
            self.assertRegex(call, r" alpine/helm:\S+@sha256:[0-9a-f]{64} ")

    def test_a_rerun_reuses_the_published_chart(self):
        self.assertEqual(self.publish().returncode, 0)
        again = self.publish()
        self.assertEqual((again.returncode, again.stdout), (0, DIGEST + "\n"), again.stderr)
        self.assertEqual(sum(" push " in call for call in self.calls()), 1)

    def test_other_content_under_a_published_version_is_refused(self):
        self.assertEqual(self.publish().returncode, 0)
        other = self.publish(epoch="1763000001")
        self.assertEqual((other.returncode, other.stdout), (1, ""))
        self.assertIn("other content", other.stderr)
        self.assertEqual(sum(" push " in call for call in self.calls()), 1)

    def test_only_a_missing_manifest_is_absence(self):
        """What the pinned helm prints when the version may exist all the same:
        refused, throttled, down, or its manifest or a blob unreadable. The
        missing-manifest line it must not be taken for is the stub's own."""
        ref = "ghcr.io/o/charts/db-mcp-gateway"
        url = "https://ghcr.io/v2/o/charts/db-mcp-gateway"
        head = f"Error: unexpected status from HEAD request to {url}/manifests/2.7.0: "
        copy = "Error: failed to copy: httpReadSeeker: failed open: "
        errors = [
            *(head + s for s in ("401 Unauthorized", "403 Forbidden", "429 Too Many Requests",
                                 "500 Internal Server Error", "503 Service Unavailable")),
            f"{copy}content at {url}/manifests/{DIGEST} not found: not found",
            f"{copy}could not fetch content descriptor {DIGEST} (application/vnd.cncf.helm"
            ".chart.content.v1.tar+gzip) from remote: not found",
            f"{copy}unexpected status code {url}/blobs/{DIGEST}: 500 Internal Server Error",
            f'Error: failed to do request: Head "{url}/manifests/2.7.0": dial tcp: i/o timeout',
            f"Error: {ref}:2.7.1: not found",
            "Error: not found",
        ]
        self.assertEqual(self.publish().returncode, 0)
        for error in errors:
            run = self.publish(PULL_ERROR=error)
            self.assertEqual((run.returncode, run.stdout), (1, ""), error)
            self.assertIn(error, run.stderr)
        self.assertEqual(sum(" push " in call for call in self.calls()), 1)

    def test_the_archive_is_reproducible(self):
        self.publish()
        with tarfile.open(os.path.join(self.tmp, "store", "chart.tgz")) as tar:
            for member in tar.getmembers():
                self.assertEqual((member.mtime, member.uid, member.gid), (1763000000, 0, 0))

    def test_a_failed_push_or_a_missing_digest_fails(self):
        for env in ({"PUSH_FAILS": "1"}, {"NO_DIGEST": "1"}):
            run = self.publish(**env)
            self.assertEqual((run.returncode, run.stdout), (1, ""), env)

    def test_only_a_release_version_is_published(self):
        for version in ("latest", "v2.7.0", "2.7", "2.7.0 --x"):
            self.assertEqual(self.publish(version=version).returncode, 2, version)
        self.assertEqual(self.publish(version="2.7.0-rc1").returncode, 0)

    def test_the_helm_pin_is_the_linted_one(self):
        self.assertEqual(
            HELM_PIN.search(read(".github/scripts/publish_chart.sh"))[1],
            HELM_PIN.search(read("bin/check-deploy"))[1],
        )


def job(workflow, name):
    return re.search(rf"^  {name}:\n((?:    .*\n|\n|  #.*\n)*)", workflow, re.M)[1]


class ReleaseWorkflow(unittest.TestCase):
    workflow = read(".github/workflows/release.yml")

    def test_the_chart_follows_the_image_and_precedes_the_announcement(self):
        self.assertIn("needs: [preflight, merge]\n", job(self.workflow, "chart"))
        self.assertIn("needs: [preflight, merge, chart]\n", job(self.workflow, "github_release"))

    def test_the_chart_never_shares_the_image_repository(self):
        self.assertIn("CHART_PARENT: ghcr.io/${{ github.repository }}/charts\n", self.workflow)

    def test_the_chart_is_pushed_signed_then_attested(self):
        chart = job(self.workflow, "chart")
        steps = ["publish_chart.sh", "cosign sign --yes", "attest-build-provenance@"]
        at = [chart.index(step) for step in steps]
        self.assertEqual(at, sorted(at))

    def test_the_chart_job_holds_no_more_than_it_needs(self):
        chart = job(self.workflow, "chart")
        granted = re.search(r"    permissions:\n((?:      .*\n)+)", chart)[1]
        self.assertEqual(
            sorted(re.findall(r"^      (\S+: \S+)$", granted, re.M)),
            ["attestations: write", "contents: read", "id-token: write", "packages: write"],
        )
        self.assertNotIn("DOCR_TOKEN", chart)


if __name__ == "__main__":
    unittest.main()
