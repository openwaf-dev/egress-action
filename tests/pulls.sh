#!/usr/bin/env bash
# Image pulls, audit then enforce: run inside a job, after the action, with a policy that starts with the
# github-actions preset alone. Pulls from Docker Hub and ghcr.io through the job's Docker (the daemon pulls) and a
# build whose base images come from both (the job builder pulls), then reads the report so far.
#   tests/pulls.sh audit    the registries, token services and layer CDNs must be in the suggested allowlist;
#                           writes it to $GITHUB_OUTPUT as allow=<comma-separated names>
#   tests/pulls.sh enforce  the same pulls must work with that allowlist, and nothing may be refused
set -euo pipefail
mode=${1:?audit or enforce}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

docker pull -q alpine:3
docker pull -q ghcr.io/linuxcontainers/alpine:latest
mkdir -p "$tmp/build"
printf 'FROM ghcr.io/linuxcontainers/alpine:latest AS ghcr\nFROM alpine:3\nCOPY --from=ghcr /etc/os-release /ghcr-os-release\n' >"$tmp/build/Dockerfile"
docker build -q -t egresspulls "$tmp/build" >/dev/null
docker run --rm egresspulls cat /ghcr-os-release >/dev/null
# The builder's connections are recorded when they close.
docker buildx stop "$BUILDX_BUILDER"
sleep 1

"$EGRESS_CI_STATE/egress-ci" report -state "$EGRESS_CI_STATE" -summary "$tmp/summary.md" >/dev/null
rep="$EGRESS_CI_STATE/report.json"
jq -r '.destinations[] | select(.connections > 0) | "\(.host)\t\(.via | join(","))\t\(.blocked) blocked\t\(.audited) audited"' "$rep"
echo "image pulls: $(jq -c '.image_pulls' "$rep")"
echo "daemon: $(jq -r '.meta.daemon' "$rep")"
echo "suggested: $(jq -c '.suggested_allow' "$rep")"

fail=0
case "$mode" in
  audit)
    for h in registry-1.docker.io auth.docker.io ghcr.io pkg-containers.githubusercontent.com; do
      jq -e --arg h "$h" '.suggested_allow | index($h)' "$rep" >/dev/null || { echo "FAIL  $h not in the suggested allowlist"; fail=1; }
    done
    jq -e '.suggested_allow | map(select(test("^production\\.cloud(flare|front)\\.docker\\.com$"))) | length > 0' "$rep" >/dev/null \
      || { echo "FAIL  no Docker Hub layer CDN in the suggested allowlist"; fail=1; }
    jq -e '[.destinations[] | select(.host == "registry-1.docker.io" or .host == "ghcr.io") | .via | index("docker")] | all' "$rep" >/dev/null \
      || { echo "FAIL  registries not recorded via docker"; fail=1; }
    echo "allow=$(jq -r '.suggested_allow | join(",")' "$rep")" >>"${GITHUB_OUTPUT:-/dev/null}"
    ;;
  enforce)
    jq -e '.blocked == 0 and .would_block == 0' "$rep" >/dev/null || { echo "FAIL  destinations refused in enforce"; fail=1; }
    ;;
esac
[ "$fail" = 0 ] && echo "ok    image pulls ($mode)"
exit $fail
