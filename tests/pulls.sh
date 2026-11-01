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
    # Each registry, token service and layer CDN: recorded from the daemon's pulls (via docker), and either in the
    # suggested allowlist or already allowed (ghcr.io is in GitHub's list for Actions, the github-actions preset).
    cdn=$(jq -r '[.destinations[].host | select(test("^production\\.cloud(flare|front)\\.docker\\.com$"))] | first // "production.cloudflare.docker.com"' "$rep")
    for h in registry-1.docker.io auth.docker.io "$cdn" ghcr.io pkg-containers.githubusercontent.com; do
      jq -e --arg h "$h" '.destinations[] | select(.host == $h) | .via | index("docker") != null' "$rep" >/dev/null \
        || { echo "FAIL  $h not recorded from the daemon's pulls"; fail=1; continue; }
      jq -e --arg h "$h" '(.suggested_allow | index($h)) or ([.destinations[] | select(.host == $h and .allowed)] | length > 0)' "$rep" >/dev/null \
        || { echo "FAIL  $h neither allowed nor in the suggested allowlist"; fail=1; }
    done
    echo "allow=$(jq -r '.suggested_allow | join(",")' "$rep")" >>"${GITHUB_OUTPUT:-/dev/null}"
    ;;
  enforce)
    jq -e '.blocked == 0 and .would_block == 0' "$rep" >/dev/null || { echo "FAIL  destinations refused in enforce"; fail=1; }
    ;;
esac
[ "$fail" = 0 ] && echo "ok    image pulls ($mode)"
exit $fail
