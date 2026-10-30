# Security policy

## Reporting a vulnerability

Email **security@openwaf.dev** with a description, the affected version or commit, and steps to reproduce. Please do
not open a public issue or pull request for a vulnerability. We confirm that we received the report, keep you
informed until a fixed release is published, and credit reporters in the release notes unless you ask us not to.

## Scope

In scope: everything in this repository — the action (`action.yml`, `start.js`, `stop.js`, `scripts/`), the sidecar
(`cmd/egress-ci`: proxy, transparent proxy, DNS forwarder, nftables lock, Docker socket, DLP, report and event
sender) and the binaries in `dist/`. Examples of what we want to hear about:

- traffic of a covered step or of one of the job's containers that reaches a destination outside the policy in
  `enforce` without root, without removing the lock and without the documented limits (README, «Limits»);
- a destination, secret or detection that the job summary, `report.json` or the events sent to OpenWAF misreport;
- a secret that the sidecar prints, logs or sends (the GitHub token, the OIDC tokens, the run CA's key);
- a way for one job to read or change another job's lock, socket or events on a shared runner;
- a `dist/` binary that does not match `dist/SHA256SUMS` or the source.

Also welcome, at the same address: issues in the OpenWAF service that receives the events (the token exchange and
the events API). Their code is not in this repository.

Out of scope: a step with root (`sudo` on GitHub-hosted runners, the docker group on self-hosted ones) removing or
bypassing the lock, steps that run before the action, and the other limits the README lists. They are known and
documented; reports that narrow them are still welcome.

## Handling secrets

The sidecar never puts a token on a command line or in a log: the GitHub token reaches `api.github.com/meta` through
curl's standard input, and the OIDC token and the token OpenWAF exchanges it for stay in the post step's memory.
The CA created for `inspect` keeps its private key in the sidecar's memory only; it is valid for 12 hours and only the
certificate is written to the runner. The job summary and `report.json` hold names, ports, counts and detection ids,
never request bodies or the secrets a detection found.
