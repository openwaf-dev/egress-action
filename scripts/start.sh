#!/usr/bin/env bash
# Starts the OpenWAF Egress CI sidecar for this job and points the following steps at it: HTTPS_PROXY, the job's
# Docker socket (DOCKER_HOST) and a job builder (BUILDX_BUILDER). Root for the lock comes from sudo (GitHub-hosted
# runners) or from Docker (self-hosted runners whose job user is in the docker group); without either the proxy and
# DNS log still run, without the lock (audit only).
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
policy=${EGRESS_POLICY:-.github/egress.yml}
mode=${EGRESS_MODE:-}
lock=${EGRESS_LOCK:-auto}
containers=${EGRESS_CONTAINERS:-track}
state="${RUNNER_TEMP:?}/egress-ci"
uid=$(id -u)
name="egress-ci-${uid}"
t0=$(date +%s%N)
ms() { echo $(( ($(date +%s%N) - t0) / 1000000 )); }

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "::error title=OpenWAF Egress CI::unsupported architecture $(uname -m)"; exit 1 ;;
esac
[ "$(uname -s)" = Linux ] || { echo "::error title=OpenWAF Egress CI::Linux runners only"; exit 1; }
[ -f "$policy" ] || { echo "::error title=OpenWAF Egress CI::policy $policy not found"; exit 1; }
case "$containers" in track | lock-all | off) ;; *) echo "::error title=OpenWAF Egress CI::containers: track, lock-all or off"; exit 1 ;; esac

rm -rf "$state"; mkdir -p "$state"; chmod 0755 "$state"
# dist/ holds gzip -n binaries (a quarter of the size to check out); the digest is of the uncompressed binary.
bin="$state/egress-ci"
gzip -dc "$here/dist/egress-ci-linux-$arch.gz" >"$bin"
( cd "$state" && grep " egress-ci-linux-$arch\$" "$here/dist/SHA256SUMS" | sed "s| egress-ci-linux-$arch\$| egress-ci|" | sha256sum -c --quiet - ) || {
  echo "::error title=OpenWAF Egress CI::dist/egress-ci-linux-$arch.gz does not match dist/SHA256SUMS"; exit 1; }
chmod 0755 "$bin"
cp "$policy" "$state/policy.yml"; chmod 0644 "$state/policy.yml"

# GitHub's published list of what Actions runners reach (exact storage account names): current copy, cached 6 h in
# HOME (one API call per runner and slot), with the token kept off argv; the binary's snapshot when it fails.
meta_cache="$HOME/.cache/egress-ci/github-meta.json"
if [ ! -s "$meta_cache" ] || [ -n "$(find "$meta_cache" -mmin +360 2>/dev/null)" ]; then
  mkdir -p "$(dirname "$meta_cache")"
  if [ -n "${EGRESS_GITHUB_TOKEN:-}" ]; then
    printf 'header = "Authorization: Bearer %s"\n' "$EGRESS_GITHUB_TOKEN" |
      curl -sSf --max-time 10 -K - -o "$meta_cache.tmp" "${GITHUB_API_URL:-https://api.github.com}/meta" && mv "$meta_cache.tmp" "$meta_cache" || rm -f "$meta_cache.tmp"
  else
    curl -sSf --max-time 10 -o "$meta_cache.tmp" "${GITHUB_API_URL:-https://api.github.com}/meta" && mv "$meta_cache.tmp" "$meta_cache" || rm -f "$meta_cache.tmp"
  fi
fi
meta_args=()
if [ -s "$meta_cache" ]; then cp "$meta_cache" "$state/github-meta.json"; chmod 0644 "$state/github-meta.json"; meta_args=(-github-meta "$state/github-meta.json"); fi
"$bin" check -policy "$state/policy.yml" "${meta_args[@]}"
t_check=$(ms)

how=none
if [ "$lock" != off ]; then
  if sudo -n true 2>/dev/null; then how=sudo
  elif docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then how=docker
  fi
fi
if [ "$how" = none ] && [ "$lock" = on ]; then
  echo "::error title=OpenWAF Egress CI::lock: on needs sudo or Docker"; exit 1
fi

# Ports below the ephemeral range, fixed per job user (two job users on one runner never share them).
base=$(( 30000 + (uid % 900) * 3 ))
hosts=127.0.0.1
docker_args=()
# The daemon the job was given: a runner may hand each job slot its own socket (to label and clean each slot's
# containers apart); the job's socket forwards to it.
dockersock=/var/run/docker.sock
case "${DOCKER_HOST:-}" in unix://*) dockersock=${DOCKER_HOST#unix://} ;; esac
if [ "$containers" != off ] && [ "$how" != none ] && [ -S "$dockersock" ] && ip -4 -o addr show docker0 >/dev/null 2>&1; then
  hosts="127.0.0.1,$(ip -4 -o addr show docker0 | awk '{print $4}' | cut -d/ -f1)"
  docker_args=(-docker "$dockersock")
  [ "$containers" = lock-all ] && docker_args+=(-lock-all-containers)
fi
args=(run -policy "$state/policy.yml" -state "$state" -uid "$uid" -hosts "$hosts" -port "$base" "${meta_args[@]}" "${docker_args[@]}")
[ -n "$mode" ] && args+=(-mode "$mode")

case "$how" in
  sudo)
    sudo -n bash -c 'nohup setsid "$@" >"$0/sidecar.log" 2>&1 & echo $! >"$0/sidecar.pid"' "$state" "$bin" "${args[@]}" -lock on
    ;;
  docker)
    # An empty image built locally: the static binary is mounted, nothing is pulled.
    docker image inspect egress-ci-scratch:1 >/dev/null 2>&1 \
      || tar -cf - --files-from /dev/null | docker import - egress-ci-scratch:1 >/dev/null
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --privileged --network host --user 0:0 \
      -v /:/host:ro -v /etc/ssl:/etc/ssl:ro -v "$state:$state" -v "$dockersock:$dockersock" \
      --entrypoint "$bin" egress-ci-scratch:1 "${args[@]}" -chroot /host -lock on >/dev/null
    ;;
  none)
    nohup setsid "$bin" "${args[@]}" -lock off >"$state/sidecar.log" 2>&1 &
    echo $! >"$state/sidecar.pid"
    ;;
esac
echo "$how" >"$state/how"

for _ in $(seq 1 200); do [ -s "$state/meta.json" ] && break; sleep 0.05; done
t_ready=$(ms)
if [ ! -s "$state/meta.json" ]; then
  echo "::error title=OpenWAF Egress CI::sidecar did not start"
  { [ "$how" = docker ] && docker logs "$name" 2>&1; cat "$state/sidecar.log" 2>/dev/null; } | tail -20 || true
  exit 1
fi
field() { sed -n "s/.*\"$1\": \"\\([^\"]*\\)\".*/\\1/p" "$state/meta.json" | head -1; }
port=$(sed -n 's/.*"127\.0\.0\.1:\([0-9]*\)".*/\1/p' "$state/meta.json" | head -1)
proxy="http://127.0.0.1:${port}"

np="localhost,127.0.0.1,::1,172.16.0.0/12,.local,.localhost,.test${EGRESS_NO_PROXY:+,$EGRESS_NO_PROXY}"
# Azure Blob (Actions cache and artifacts) skips HTTPS_PROXY when the lock is on: @actions/cache opens one CONNECT
# tunnel per 4 MB chunk through a proxy (no keep-alive, TCP slow start on every chunk). Those connections still go
# through the sidecar, in the transparent proxy: named by SNI, only the exact accounts of the policy (GitHub's list),
# and the address must be one of that name.
[ "$(field lock)" = on ] && np="$np,.blob.core.windows.net"
{
  echo "HTTP_PROXY=$proxy"; echo "HTTPS_PROXY=$proxy"; echo "http_proxy=$proxy"; echo "https_proxy=$proxy"
  echo "NO_PROXY=$np"; echo "no_proxy=$np"
  echo "EGRESS_CI_STATE=$state"
} >>"$GITHUB_ENV"
if [ -s "$state/ca.pem" ]; then
  cat /etc/ssl/certs/ca-certificates.crt "$state/ca.pem" >"$state/bundle.pem"
  {
    echo "NODE_EXTRA_CA_CERTS=$state/ca.pem"; echo "SSL_CERT_FILE=$state/bundle.pem"
    echo "REQUESTS_CA_BUNDLE=$state/bundle.pem"; echo "CURL_CA_BUNDLE=$state/bundle.pem"; echo "GIT_SSL_CAINFO=$state/bundle.pem"
  } >>"$GITHUB_ENV"
fi
if [ "$(field docker)" = tracked ]; then
  # The job's Docker goes through its own socket; `docker build` uses a job builder container (tracked like any
  # container of the job) that loads its images into the daemon, instead of the daemon's builder, whose build
  # steps run in sandboxes no job can be told apart in.
  export DOCKER_HOST="unix://$state/docker.sock"
  docker buildx create --name "$name" --driver docker-container --driver-opt default-load=true >/dev/null
  { echo "DOCKER_HOST=$DOCKER_HOST"; echo "BUILDX_BUILDER=$name"; } >>"$GITHUB_ENV"
fi
echo "proxy=$proxy" >>"$GITHUB_OUTPUT"
total=$(ms)
echo "$total" >"$state/start_ms"
echo "OpenWAF Egress CI: proxy $proxy, lock $(field lock) (via $how), Docker $(field docker), GitHub preset $(field github_meta), started in ${total} ms (binary, policy and GitHub list ${t_check} ms, sidecar ready ${t_ready} ms)"
