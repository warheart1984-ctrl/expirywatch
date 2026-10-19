# expirywatch

A small command-line tool that warns you before things expire: TLS certificates, domain registrations, and any date an HTTP API reports (licenses, API keys, tokens).

Run it once a day from cron, Task Scheduler or CI. It prints a table, can post a report to Slack, Discord or any webhook, and exits non-zero when something needs attention.

```
NAME               TYPE    ADDRESS                        STATUS    EXPIRES               DAYS LEFT
github.com TLS     tls     github.com:443                 OK        2026-11-29 23:59 UTC  42
github.com domain  domain  github.com                     OK        2028-10-09 18:20 UTC  722
expired cert       tls     expired.badssl.com:443         CRITICAL  2015-04-12 23:59 UTC  -4207
untrusted root     tls     untrusted-root.badssl.com:443  ERROR     -                     -

error: untrusted root (untrusted-root.badssl.com:443): certificate verification failed: x509: certificate signed by unknown authority

summary: 2 ok, 0 warn, 1 critical, 1 error (total 4)
```

## Download

Prebuilt binaries for Windows, Linux and macOS (amd64 and arm64) are attached to each [GitHub release](https://github.com/warheart1984-ctrl/expirywatch/releases/latest). Download the one for your system, rename it to `expirywatch` (or `expirywatch.exe` on Windows) and put it somewhere on your `PATH`. On Linux and macOS, make it executable with `chmod +x expirywatch`.

Each release also has a `SHA256SUMS` file to check the download:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

## Install from source

Needs Go 1.27 or newer.

```bash
go install github.com/warheart1984-ctrl/expirywatch@latest
```

Or clone and build:

```bash
git clone https://github.com/warheart1984-ctrl/expirywatch
cd expirywatch
go build
```

## Usage

```bash
cp config.example.json config.json
expirywatch --config config.json
```

| Flag | Meaning |
|---|---|
| `--config PATH` | Config file (default `config.json`) |
| `--json` | Print results as JSON instead of a table |
| `--no-webhook` | Don't send the webhook this run |
| `--version` | Print the version |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything is OK or only warnings |
| `1` | At least one target is CRITICAL |
| `2` | At least one check failed (ERROR) |
| `3` | Bad config or flags |

## Target types

### `tls`: certificate expiry

```json
{ "name": "my site", "type": "tls", "address": "example.com:443" }
```

Connects to the server and reports the **earliest expiry anywhere in the chain it presents**, so an intermediate certificate that runs out before your own certificate is caught. The chain is verified against the system trust store; an untrusted or mismatched certificate is reported as ERROR. An already expired certificate is reported as CRITICAL with negative days left. The port defaults to 443.

### `domain`: registration expiry

```json
{ "name": "my domain", "type": "domain", "address": "example.com" }
```

Looks up the expiration date through [RDAP](https://about.rdap.org/). At the start of each run, expirywatch fetches the [IANA RDAP bootstrap file](https://data.iana.org/rdap/dns.json) once and asks the TLD's own registry. If the TLD isn't listed there, or the file can't be fetched, it falls back to rdap.org.

Most generic TLDs (`.com`, `.net`, `.org`, `.dev`, ...) work. A TLD with no RDAP service at all reports an ERROR such as `no RDAP service for .de`. Some registries run RDAP but don't publish expiry dates; those report `no expiration event`.

### `http`: any expiry date in a JSON API

```json
{
  "name": "license server",
  "type": "http",
  "address": "https://api.example.com/v1/license",
  "expiry_path": "data.expires_at",
  "token_env": "LICENSE_API_TOKEN"
}
```

Fetches the URL and reads the date at `expiry_path` (dot-separated keys; numbers index into arrays, such as `items.0.expires`). The value can be an RFC 3339 timestamp, a `YYYY-MM-DD` date, or a Unix timestamp in seconds or milliseconds. If `token_env` is set, the environment variable's value is sent as `Authorization: Bearer <token>`.

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `warn_days` | `30` | WARN when this many days or fewer are left |
| `critical_days` | `7` | CRITICAL when this many days or fewer are left |
| `timeout` | `10s` | Per-check timeout (Go duration) |
| `webhook_url` | empty | Where to POST the report; empty disables it |
| `webhook_format` | `json` | `json`, `slack` or `discord` |
| `webhook_skip_ok` | `false` | Only send the webhook when something is not OK |
| `targets` | required | List of targets |

`warn_days`, `critical_days` and `timeout` can also be set per target.

### Secrets from the environment

`webhook_url` and the `address` of `http` targets can reference environment variables as `${NAME}`, so webhook URLs and API keys don't have to live in `config.json`:

```json
{
  "webhook_url": "${SLACK_WEBHOOK_URL}",
  "targets": [
    { "name": "license", "type": "http", "address": "https://api.example.com/v1/license?key=${LICENSE_KEY}", "expiry_path": "expires_at" }
  ]
}
```

- Only the braced form `${NAME}` is expanded. A lone `$` or `$NAME` is left as it is. Write `$${` for a literal `${`.
- If a referenced variable is unset or empty, expirywatch stops with a config error (exit code 3) that names the variable.
- Addresses are shown as written, with `${NAME}` and not the value, in the table, `--json` output and webhook reports. Error messages leave out the expanded URL too.

## Notifications

- **`slack`**: Create a Slack [incoming webhook](https://api.slack.com/messaging/webhooks) and paste its URL.
- **`discord`**: In a channel's settings, open Integrations, then Webhooks, and copy the URL.
- **`json`**: Posts the full result set (the same shape as `--json`) for your own service or automation tool.

Slack and Discord get a short message listing only the targets that need attention:

```
expirywatch: 1 critical, 1 warn, 0 error, 3 ok (total 5)
- CRITICAL shop (shop.example.com:443): expires 2026-10-22 (3 days left)
- WARN blog domain (blog.example.org): expires 2026-11-10 (22 days left)
```

Set `"webhook_skip_ok": true` to stay quiet on days when everything is fine.

If the webhook fails with a network error or a 5xx response, expirywatch waits 2 seconds and tries once more. A 4xx response, like a wrong or revoked URL, is not retried. A failed webhook is reported on stderr and doesn't change the exit code.

## Running it daily

**Windows** (Task Scheduler):

```powershell
.\scripts\install-schedule.ps1 -ConfigPath C:\path\to\config.json -Time 09:00
.\scripts\install-schedule.ps1 -Uninstall
```

**Linux / macOS** (cron, daily at 09:00):

```
0 9 * * * /usr/local/bin/expirywatch --config /etc/expirywatch/config.json
```

**GitHub Actions**, a scheduled workflow:

```yaml
on:
  schedule:
    - cron: "0 9 * * *"
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.27"
      - run: go run github.com/warheart1984-ctrl/expirywatch@latest --config config.json
```

## License

MIT
