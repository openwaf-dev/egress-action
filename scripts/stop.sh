#!/usr/bin/env bash
# Stops the sidecar (it removes its nftables table and dumps what the lock saw), then writes the report.
set -uo pipefail

state="${RUNNER_TEMP:?}/egress-ci"
[ -d "$state" ] || { echo "OpenWAF Egress CI: nothing to stop"; exit 0; }
bin="$state/egress-ci" # extracted and checked by start.sh
uid=$(id -u)
how=$(cat "$state/how" 2>/dev/null || echo none)
t0=$(date +%s%N)

# The job builder goes first, through the job's socket while the sidecar still serves it. Its BuildKit state (the
# volume buildx_buildkit_egress-ci-<uid>0_state, cache of base images and layers) is kept, bounded to 4 GB, for the
# next job of the same runner user: on persistent and slot runners that saves the base image pulls of every build.
if [ -S "$state/docker.sock" ]; then
  export DOCKER_HOST="unix://$state/docker.sock"
  docker buildx prune --builder "egress-ci-${uid}" -f --keep-storage 4gb >/dev/null 2>&1
  docker buildx rm --keep-state -f "egress-ci-${uid}" >/dev/null 2>&1
  unset DOCKER_HOST
fi
case "$how" in
  docker)
    docker stop -t 15 "egress-ci-${uid}" >/dev/null 2>&1
    docker logs "egress-ci-${uid}" >"$state/sidecar.log" 2>&1
    docker rm -f "egress-ci-${uid}" >/dev/null 2>&1
    ;;
  sudo)
    pid=$(cat "$state/sidecar.pid" 2>/dev/null)
    [ -n "$pid" ] && sudo -n kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 150); do sudo -n kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    ;;
  none)
    pid=$(cat "$state/sidecar.pid" 2>/dev/null)
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
    for _ in $(seq 1 150); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    ;;
esac

send=()
[ "${EGRESS_SEND_EVENTS:-off}" = on ] && send=(-send -api "${EGRESS_OPENWAF_API:-https://dash.openwaf.dev}")
"$bin" report -state "$state" -summary "${GITHUB_STEP_SUMMARY:-}" "${send[@]}" || exit 1
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
echo "OpenWAF Egress CI: stopped and reported in ${ms} ms (start $(cat "$state/start_ms" 2>/dev/null) ms)"
# One line for collection across runs (no secrets: names, ports, counts and detection ids only).
echo "::group::egress-ci report.json"
cat "$state/report.json"
echo
echo "::endgroup::"
grep -h '"lock"\|error' "$state/sidecar.log" 2>/dev/null | tail -5
exit 0
