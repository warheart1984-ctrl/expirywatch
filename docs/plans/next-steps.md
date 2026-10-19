# expirywatch: plan for v0.3.0

Handoff plan for the next agent. Written 2026-10-19.

## Current state

- Repo: https://github.com/warheart1984-ctrl/expirywatch (public), branch `main`, commit `d60cf4c`, version `0.2.0`.
- Local checkout: `D:\repos\expirywatch` (Windows 10, Go 1.27.1, gh logged in as `warheart1984-ctrl`).
- `go vet ./...` and `go test ./...` pass (15 tests). Live checks against github.com and badssl.com behave as documented in the README.
- Not done: no scheduled task is registered on the user's PC (no real `config.json` exists yet). `expirywatch.exe` and `config.json` are gitignored.

## Ground rules

- One commit per step below, with tests. Run `gofmt -l .`, `go vet ./...` and `go test ./...` before each commit.
- Ask the user before pushing, tagging or publishing a release.
- Keep it dependency-free (standard library only) unless a step says otherwise.
- Write files as UTF-8 with LF endings. Python on this machine defaults to cp1252, so pass `encoding='utf-8', newline='\n'`.

## Steps

### 1. CI workflow
Add `.github/workflows/ci.yml`: on push and pull request, run gofmt check, `go vet` and `go test` on `ubuntu-latest` and `windows-latest` with Go 1.27.
Done when the workflow passes on GitHub.

### 2. Prebuilt release binaries
Add a release workflow triggered by `v*` tags that builds windows/linux/darwin for amd64 and arm64 with `-ldflags "-s -w"` and attaches them to a GitHub release. Plain `go build` in a matrix is fine; GoReleaser is optional. Add a "Download" section to the README.
Done when tagging `v0.3.0` (after asking the user) produces a release with 6 binaries.

### 3. Secrets out of the config file
Expand `${VAR}` in `webhook_url` (and in `address` for `http` targets) from the environment, so Slack/Discord webhook URLs don't have to live in `config.json`. Error clearly when a referenced variable is unset. Document it in the README.
Done when tests cover set, unset and literal `$` cases.

### 4. Webhook reliability
Retry the webhook once after 2s on a network error or 5xx. Add an end-to-end test using `httptest.Server` that checks the body for each `webhook_format` and the retry.
Done when tests cover success, a 500 followed by success, and a 400 (no retry).

### 5. Better domain lookups
Replace the rdap.org redirector with the IANA bootstrap file (`https://data.iana.org/rdap/dns.json`): fetch once per run, pick the registry's RDAP server for the TLD, and fall back to rdap.org if the TLD isn't listed. When a TLD has no RDAP service at all, return a clear error such as `no RDAP service for .de`.
Done when tests use a fake bootstrap file and fake registry via `httptest`.

### 6. Check every IP behind a hostname (optional, ask first)
Add a per-target option `"all_ips": true` for `tls` targets: resolve the host, check each address with SNI set to the hostname, and report the earliest expiry and which IP served it. This catches load balancers where one node has a stale certificate.

## Out of scope

- A web UI, a database, or running as a long-lived service. The tool stays a single run-once binary.
