#!/usr/bin/env bash
# Builds dist/egress-ci-linux-{amd64,arm64}.gz reproducibly (gzip -n) and writes dist/SHA256SUMS of the uncompressed
# binaries.
#   scripts/build-dist.sh          rebuild dist/
#   scripts/build-dist.sh --check  rebuild into a temp dir and fail if dist/ differs (CI)
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(cat VERSION)
out=dist
if [ "${1:-}" = --check ]; then out=$(mktemp -d); trap 'rm -rf "$out"' EXIT; fi
mkdir -p "$out"
tmp=$(mktemp -d)
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=$version" -o "$tmp/egress-ci-linux-$arch" ./cmd/egress-ci
  gzip -n -9 -c "$tmp/egress-ci-linux-$arch" >"$out/egress-ci-linux-$arch.gz"
done
( cd "$tmp" && sha256sum egress-ci-linux-amd64 egress-ci-linux-arm64 >SHA256SUMS ) && cp "$tmp/SHA256SUMS" "$out/SHA256SUMS"
rm -rf "$tmp"
if [ "$out" != dist ]; then
  diff "$out/SHA256SUMS" dist/SHA256SUMS || { echo "dist/ is not the build of this source (go $(go env GOVERSION)): run scripts/build-dist.sh"; exit 1; }
  # gzip output differs between implementations: compare what the archives hold, not their bytes.
  for arch in amd64 arm64; do
    [ "$(gzip -dc "dist/egress-ci-linux-$arch.gz" | sha256sum | cut -d' ' -f1)" = "$(grep " egress-ci-linux-$arch\$" dist/SHA256SUMS | cut -d' ' -f1)" ] \
      || { echo "dist/egress-ci-linux-$arch.gz does not hold the binary of SHA256SUMS"; exit 1; }
  done
  echo "dist/ matches the source"
fi
