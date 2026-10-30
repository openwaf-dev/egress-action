# OpenWAF Egress CI

[Español](README.es.md)

A GitHub Action that puts a job's outbound traffic behind an allowlist. Every connection and DNS query of the job and
of its containers is named and logged; anything outside `.github/egress.yml` is reported (`audit`) or refused
(`enforce`); what leaves is checked for secrets with the [OpenWAF Egress](https://github.com/openwaf-dev/egress)
detectors; and the job summary lists every destination the job talked to.

It runs as a sidecar inside the job, on the runner itself: no account, no service and no data sent anywhere unless
you turn on [`send-events`](#send-events-to-openwaf). Early-access beta.

Linux runners, x64 and arm64: GitHub-hosted, or self-hosted where the job user reaches root through `sudo` or the
Docker daemon.

Product documentation: [developers.openwaf.dev/egress/ci/quickstart/](https://developers.openwaf.dev/egress/ci/quickstart/).

## Quickstart

1. Add the action as the first step after checkout (the steps before it are not covered):

   ```yaml
   steps:
     - uses: actions/checkout@v4
     - uses: openwaf-dev/egress-action@v0.3.1
     - run: make test
   ```

   For production, pin the full commit SHA of the release instead of the tag (a tag can be moved; a SHA cannot),
   with the version as a comment so Dependabot can update it:
   `uses: openwaf-dev/egress-action@<40-character SHA of v0.3.1> # v0.3.1`.

2. Commit `.github/egress.yml`:

   ```yaml
   version: 1
   mode: audit                 # audit: report only; enforce: refuse the rest
   presets: [github-actions]   # GitHub's published list for Actions runners (api.github.com/meta), exact names
   allow:
     - proxy.golang.org        # ports 80 and 443
     - "*.npmjs.org"           # any name below npmjs.org (not npmjs.org itself)
     - registry.example.com:5000
   inspect: []                 # hosts whose TLS is terminated to scan request bodies (see below)
   ```

3. Run the workflow, open the job summary and copy the names it lists under «Names outside the policy» into
   `allow`. Once a few runs are clean, set `mode: enforce`.

More workflows in [`examples/`](examples/): first run in audit, enforce, Docker builds, a self-hosted runner with
`sudo`, a monorepo with one policy per job, and sending events to OpenWAF.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `policy` | `.github/egress.yml` | Policy file. |
| `mode` | empty | `audit` or `enforce`; overrides `mode` in the file. |
| `lock` | `auto` | nftables lock scoped to the job's user: `auto` (on when root is reachable through `sudo` or Docker), `on` (the step fails when root is not reachable), `off`. Without the lock only `HTTPS_PROXY` is covered; in enforce, a lock that cannot be installed fails the step. |
| `containers` | `track` | `track`: the job's Docker goes through its own socket; its containers and builds are attributed and held to the policy like the job. `lock-all`: also refuse every other container's traffic outside the policy (runners that run one job at a time). `off`: Docker untouched. |
| `no-proxy` | empty | Extra comma-separated `NO_PROXY` entries. |
| `token` | `github.token` | Reads `api.github.com/meta` for the `github-actions` preset. |
| `send-events` | `off` | `on`: send the job's destinations, blocks and detections to your organization's OpenWAF Egress events. Needs `permissions: id-token: write`. A failure never fails the job. |
| `openwaf-api` | `https://dash.openwaf.dev` | OpenWAF API for `send-events`. |

Output: `proxy` (`http://127.0.0.1:PORT`).

The action sets for the following steps `HTTPS_PROXY`, `HTTP_PROXY` (and the lowercase forms), `NO_PROXY`
(`localhost`, `127.0.0.1`, `::1`, `172.16.0.0/12`, `.local`, `.localhost`, `.test` and your `no-proxy`),
`EGRESS_CI_STATE`; with Docker tracking `DOCKER_HOST` and `BUILDX_BUILDER`; with `inspect` the CA variables listed
under [Limits](#limits).

## Policy

| Key | Meaning |
|---|---|
| `version` | `1`. |
| `mode` | `audit` (default) or `enforce`. |
| `presets` | `github-actions`: the names GitHub publishes for Actions runners in `api.github.com/meta` (fetched at start and cached 6 hours; a snapshot built into the binary when the fetch fails), with Azure storage accounts by exact name, plus `raw.githubusercontent.com`. |
| `allow` | `host` (ports 80 and 443), `*.domain` (any name below it, not the domain itself), `host:5000`, `host:80,8080`, `host:*` (any port). Names are case-insensitive; an IPv4 address is accepted as a host. |
| `inspect` | Hosts whose TLS the proxy terminates to scan request bodies. Same syntax as `allow`. |

Unknown keys are an error: a typo fails the step instead of silently allowing nothing.

## How it works

| Piece | What it does |
|---|---|
| Proxy | `HTTPS_PROXY`/`HTTP_PROXY` for the following steps. `CONNECT` tunnels are checked by name and by the TLS SNI (an SNI outside the policy is refused); not decrypted unless the host is under `inspect`. Loopback, link-local (cloud metadata) and multicast destinations are refused. |
| Lock | An nftables table matching only the job user's sockets: its DNS goes to the forwarder and every other TCP connection to a transparent proxy (the runner itself, tools that ignore the proxy variables). Other flows (UDP, ICMP, IPv6) outside the policy are refused in enforce. |
| Transparent proxy | Names each connection from its TLS SNI or HTTP Host, checks the name against the policy and that the address it was sent to is one the name resolves to (an allowed SNI sent elsewhere is domain fronting and is refused). A connection without a name passes only to an address an allowed name resolved to. |
| DNS | Every name is recorded with who asked; names outside the policy get NXDOMAIN in enforce; long high-entropy labels (data encoded into names) are flagged. |
| Docker | `DOCKER_HOST` points at a socket the sidecar serves. The job's networks are held by subnet from their creation (a container asking for the default bridge gets the job's own network), so a container is covered from its first packet: its DNS and TCP go through the same forwarder and transparent proxy, attributed per container, and the rest is refused in enforce. Containers, networks and volumes get a label. Image pulls are checked by registry before the daemon fetches anything. `docker build` uses a job builder container (`BUILDX_BUILDER`, loads into the daemon), so build steps are the job's too; its BuildKit cache is kept for the next job of the same runner user, up to 4 GB. |
| DLP | URL, headers and textual bodies up to 4 MiB of plain HTTP and of inspected HTTPS are scanned: private keys, AWS access keys, `sk-` keys, GitHub tokens (except to GitHub), payment cards (Luhn). In enforce the request is refused. |
| Report | The job summary: destinations with ports, path (proxy, direct, container, udp), bytes, containers, image pulls, names outside the policy, detections. `report.json` in the post step's log. |

## Send events to OpenWAF

With `send-events: on` and `permissions: id-token: write`, the post step asks GitHub for an OIDC token (audience
`openwaf-egress-ci`), exchanges it at the OpenWAF API for a token that lasts 15 minutes, and sends one event per
destination (host, port, path, container, decision, reason, detection ids, connection and byte counts) with the
run's identity (repository, workflow, job, run id and attempt, commit, ref, event, runner name). Never request
bodies, headers or URLs. The repository must be registered in an OpenWAF organization with Egress enabled. If
anything fails (no `id-token: write`, an unregistered repository, the network), the summary says why and the job
goes on. See [the documentation](https://developers.openwaf.dev/egress/ci/send-events/).

## Limits

- Only the steps after the action are covered. A step with root can remove the lock: on GitHub-hosted runners every
  job has `sudo`, and on self-hosted runners the docker group is root-equivalent. The action raises the cost of
  exfiltration by a dependency or a tool; it is not a boundary against code that sets out to escape it.
- Docker used without `DOCKER_HOST` (a tool that opens `/var/run/docker.sock` itself) is not attributed; with
  `lock-all` its traffic outside the policy is refused anyway, otherwise it is listed as not this job's. Containers
  with `--network host` are outside the lock unless they run as the job's user.
- Image pulls are made by the daemon: the registry is checked, the daemon's own connections are not proxied.
- Without `inspect`, request bodies over HTTPS are not scanned: the proxies see the destination, not the content.
  Inspecting needs the job to trust a CA created for the run (exported as `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`); tools with their own trust store or pinning fail.
  Inspection applies to connections made through `HTTPS_PROXY`, over HTTP/1.1.
- Destinations in `172.16.0.0/12` (Docker's address pool) are left to the runner's own rules.
- IPv4 only for TCP naming; the job's IPv6 is refused in enforce.
- One job per runner user at a time (the lock and the ports are per user).

## Build

`scripts/build-dist.sh` builds `dist/` reproducibly (Go version from `go.mod`; binaries stored as `gzip -n`, digests
of the uncompressed binaries in `dist/SHA256SUMS`, checked before every run); CI checks that `dist/` matches the
source and runs the containment probes (`tests/probes.sh`) on GitHub-hosted runners in audit and in enforce.

## Security

Report vulnerabilities privately to **security@openwaf.dev** (see [SECURITY.md](SECURITY.md)); never in a public
issue.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).

## Licence

[Apache License 2.0](LICENSE). © OpenWAF.
