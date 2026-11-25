#!/usr/bin/env bash
# Package deploy/helm/db-mcp-gateway as chart <version> (appVersion too), push
# it to the OCI repository <parent>/db-mcp-gateway and print the pushed digest.
#
#   publish_chart.sh <version> <parent>   # e.g. 2.7.0 ghcr.io/developerz-ai/db-mcp-gateway/charts
#
# The archive is byte-reproducible for one commit (sorted, commit-time mtimes),
# so a re-run of a failed release recognises its own chart: the version already
# published with these bytes is reused, with any other bytes it fails. A
# published version never moves. Docker only; the credentials are docker's own.
set -euo pipefail
cd "$(dirname "$0")/../.."

# The helm bin/check-deploy linted this chart with.
HELM=alpine/helm:3.16.4@sha256:9b25e60ae264940b276e32866d37e3088e70c4e2d1784b964dc3f90346281a74
CHART=db-mcp-gateway

version=${1:?usage: publish_chart.sh <version> <oci parent>}
parent=${2:?usage: publish_chart.sh <version> <oci parent>}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || { echo "not a release version: $version" >&2; exit 2; }
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/packaged" "$work/tree"
as_me=(--user "$(id -u):$(id -g)" -e HOME=/tmp)

docker run --rm --network=none "${as_me[@]}" -v "$PWD/deploy:/deploy:ro" -v "$work/packaged:/out" \
  "$HELM" package "/deploy/helm/$CHART" --version "$version" --app-version "$version" -d /out >&2

archive=$CHART-$version.tgz
tar -xzmf "$work/packaged/$archive" -C "$work/tree"
tar --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --mode=u=rwX,go=rX \
  -C "$work/tree" -cf - "$CHART" | gzip -n > "$work/$archive"

# helm against the registry, on stderr and stdout both (it reports on either).
registry() {
  docker run --rm "${as_me[@]}" -v "$work:/work" \
    -v "${DOCKER_CONFIG:-$HOME/.docker}/config.json:/docker-config.json:ro" \
    "$HELM" "$@" --registry-config /docker-config.json 2>&1
}

mkdir "$work/published"
if report=$(registry pull "oci://$parent/$CHART" --version "$version" -d /work/published); then
  cmp -s "$work/$archive" "$work/published/$archive" \
    || { echo "$parent/$CHART:$version is already published with other content" >&2; exit 1; }
  echo "$parent/$CHART:$version is already published with this content" >&2
else
  printf '%s\n' "$report" >&2
  # Only this line, whole, is the registry's 404 for the manifest itself. Any
  # other failure (refused, down, a blob it could not read) may hide a chart
  # already published, which a push would replace.
  grep -qxF "Error: $parent/$CHART:$version: not found" <<< "$report" \
    || { echo "cannot tell whether $parent/$CHART:$version is published; not pushing" >&2; exit 1; }
  report=$(registry push "/work/$archive" "oci://$parent") || { printf '%s\n' "$report" >&2; exit 1; }
fi
printf '%s\n' "$report" >&2

digest=$(sed -n 's/^Digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' <<< "$report")
[[ -n $digest ]] || { echo 'helm reported no digest' >&2; exit 1; }
printf '%s\n' "$digest"
