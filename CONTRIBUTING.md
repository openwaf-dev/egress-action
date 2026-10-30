# Contributing

Thanks for helping. Issues and pull requests are welcome in English or Spanish.

## Before you start

- Security problems go to security@openwaf.dev, never to an issue ([SECURITY.md](SECURITY.md)).
- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Keep the constraints of the action: no dependencies at run time beyond what a Linux runner has (bash, curl, gzip,
  sha256sum, nftables, iproute2, the runner's Node.js), no network access by the action itself except
  `api.github.com/meta`, the job builder's image (`moby/buildkit`, pulled by the Docker daemon on the first build) and,
  with `send-events: on`, the OpenWAF API; no token on a command line or in a log; and nothing in the job summary or
  `report.json` beyond names, ports, counts and detection ids.

## Layout and checks

| Part | What |
|---|---|
| `action.yml`, `start.js`, `stop.js` | The action: inputs, and the main and post steps (no npm dependencies). |
| `scripts/start.sh`, `scripts/stop.sh` | Start the sidecar with the lock and point the following steps at it; stop it and write the report. |
| `cmd/egress-ci/` | The sidecar, in Go. |
| `dist/` | The sidecar built for linux/amd64 and linux/arm64 (`gzip -n`) and `SHA256SUMS`. |
| `tests/probes.sh` | Containment probes, run inside a job after the action, in audit and in enforce. |
| `examples/` | Workflow examples. |

Run before a pull request:

```sh
gofmt -l .                        # no output
go vet ./...
go test -race -count=1 ./...
scripts/build-dist.sh             # after any change under cmd/: commit the rebuilt dist/
scripts/build-dist.sh --check     # what CI runs: dist/ must be the reproducible build of the source
shellcheck -S warning scripts/*.sh tests/*.sh
scripts/leak-guard.sh --history .
```

`dist/` must be built with the Go toolchain `go.mod` names (`GOTOOLCHAIN=local` with that version installed), or the
check fails. The probes need a real runner: CI runs them on GitHub-hosted runners in both modes.

## How changes ship

The action is released from this repository with a `vX.Y.Z` tag, `VERSION` and `dist/` built from the same commit,
and a [CHANGELOG](CHANGELOG.md) entry. Pin the action to a tag or, better, to that tag's commit SHA.

## Commits

One logical change per pull request, a message that says what changes and why, and tests for behaviour you add or
fix. By contributing you agree that your contribution is licensed under the Apache License 2.0.
