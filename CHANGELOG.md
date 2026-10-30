# Changelog

All notable changes to this repository. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Early-access beta; the first tagged release is 0.3.1.

## [Unreleased]

## [0.3.2] - 2026-10-30

### Changed

- GitHub Marketplace metadata only: the `description` in `action.yml` is shorter (the Marketplace accepts fewer than
  125 characters). No change in behavior; the binaries in `dist/` differ only in the version they report.

## [0.3.1] - 2026-10-30

### Added

- Publication files: README in English and Spanish, `SECURITY.md`, `CONTRIBUTING.md`, this changelog and workflow
  examples in `examples/`.
- Leak guard (`scripts/leak-guard.sh`, over the tree and, with `--history`, every version of every file and every
  commit) and the `guard` workflow (gitleaks over the whole history and the leak guard with the private denylist).

### Fixed

- `send-events` from the post step: it connects directly instead of through `HTTPS_PROXY`, which still points at the
  stopped sidecar there (inside the lock a direct connection goes through the transparent proxy anyway). The
  `id-token: write` hint is only shown when the OIDC token is not available.

## [0.3.0] - 2026-10-30

### Added

- `send-events: on`: the post step exchanges the job's GitHub OIDC token (audience `openwaf-egress-ci`) at the
  OpenWAF API (`openwaf-api`, default `https://dash.openwaf.dev`) for a short-lived token and sends one event per
  destination to the organization's Egress events, in batches of up to 1000 with three attempts per batch. A failure
  is a warning and a line in the summary; it never fails the job. The job needs `permissions: id-token: write`.
- The job builder keeps its BuildKit state between jobs of the same runner user, pruned to 4 GB.
- Containment probes as `tests/probes.sh`, run by CI on GitHub-hosted runners in audit and in enforce.

### Changed

- The nftables table is named `egress_ci_<uid>`.

## [0.2.3] - 2026-10-30

### Fixed

- The job's Docker networks are held by subnet from their creation and a container asking for the default bridge
  gets the job's own network, so a container's first packets cannot leave before the lock knows it. Before, a
  container that connected as soon as it started could get out before its address was tracked.

## [0.2.2] - 2026-10-30

### Added

- `docker-label` command: a Docker socket that labels and records every container, network and volume created through
  it, for runners that clean one job slot at a time.

### Changed

- The job's Docker socket forwards to the `DOCKER_HOST` the runner gave the job, not always to
  `/var/run/docker.sock`.

## [0.2.1] - 2026-10-30

### Changed

- With the lock on, Azure Blob (Actions cache and artifacts) skips `HTTPS_PROXY` (`NO_PROXY`), because the cache
  client opens one tunnel per 4 MB chunk; those connections go through the transparent proxy, still limited to the
  exact storage accounts GitHub publishes.
- Connections to the runner's own addresses are not redirected.

## [0.2.0] - 2026-10-30

### Added

- Transparent proxy for every TCP connection of the job: named by TLS SNI or HTTP Host and checked against the
  address it was sent to (no domain fronting).
- The job's Docker socket: containers labelled, tracked and held to the policy; image pulls checked by registry; a
  job builder for `docker build`.
- `github-actions` preset from `api.github.com/meta`, with exact storage account names.

### Changed

- The sidecar's ports are below the ephemeral range, fixed per job user.

## [0.1.0] - 2026-10-29

### Added

- Allowlist proxy (`HTTPS_PROXY`), logging DNS forwarder, nftables lock scoped to the job's user, DLP with the OpenWAF
  Egress detectors, and a job summary report, in `audit` and `enforce`.
- `dist/` holds `gzip -n` binaries checked against `dist/SHA256SUMS` before every run; container connections not
  attributable to the job are listed apart.

[Unreleased]: https://github.com/openwaf-dev/egress-action/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/openwaf-dev/egress-action/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/openwaf-dev/egress-action/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/openwaf-dev/egress-action/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/openwaf-dev/egress-action/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/openwaf-dev/egress-action/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/openwaf-dev/egress-action/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/openwaf-dev/egress-action/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/openwaf-dev/egress-action/releases/tag/v0.1.0
