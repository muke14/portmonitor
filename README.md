# PortMonitor

PortMonitor is a Flask app with a browser dashboard and CLI for authorized TCP
and UDP port monitoring. The dashboard streams scan results over WebSockets;
accounts, sessions, and saved machines are stored in local JSON files.

## Requirements and setup

- Python 3.10+
- Dependencies in `requirements.txt`

From the project directory:

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>, register an account, and select the machine or
host you are authorized to assess. `start.bat` starts the same local server on
Windows.

The server binds to `127.0.0.1` by default. If you configure a non-loopback
bind, you must set an IPv4 scan-target allowlist. Keep the application behind a
TLS reverse proxy for remote browser access; do not expose its built-in
HTTP-only development server to the public internet.

Example for a trusted lab subnet in PowerShell:

```powershell
$env:PORTMONITOR_ALLOWED_TARGETS = "192.168.1.0/24,127.0.0.1"
$env:PORTMONITOR_HOST = "0.0.0.0"
python app.py
```

The allowlist limits targets that the application can probe; it does not add
HTTPS. Choose only ranges you own or are explicitly authorized to assess.

## Dashboard

- Set a port range from 1 to 65535 and a timeout from 0.1 to 3 seconds.
- TCP and UDP scan independently; UDP silence is reported as
  `open|filtered`, not confirmed open.
- Browse live results, use status/risk/search filters, and export the current
  scan as CSV.
- The dashboard intentionally says internet exposure is **not measured**.
  Reliable public exposure testing requires a separate external vantage point.

## CLI

Scan a small local TCP range:

```powershell
python app.py --cli 127.0.0.1 --start 1 --end 1024
```

Scan UDP:

```powershell
python app.py --cli 127.0.0.1 --start 1 --end 1024 --udp
```

Filter output:

```powershell
python app.py --cli 127.0.0.1 --filter critical
python app.py --cli 127.0.0.1 --filter filtered
python app.py --cli 127.0.0.1 --filter all
```

| Option | Default | Description |
| --- | --- | --- |
| `host` | `127.0.0.1` | IPv4 address or resolvable IPv4 hostname |
| `--start` | `1` | First port, inclusive |
| `--end` | `1024` | Last port, inclusive |
| `--timeout` | `0.5` | Timeout, from 0.1 to 3 seconds |
| `--workers` | `100` | CLI concurrency, from 1 to 300 |
| `--filter` | `open` | `all`, `open`, `closed`, `filtered`, or `critical` |
| `--udp` | off | Scan UDP instead of TCP |

TCP connection refusals are reported as closed; timeouts and other
unconfirmed connection failures are reported as filtered. CLI and dashboard
port ranges and concurrency are bounded. Always obtain
authorization before scanning; service names, OS fingerprints, and risk labels
are heuristics and are not vulnerability findings.

## Data and security

Runtime data lives in `data/users.json`, `data/sessions.json`, and
`data/machines.json`. These files are excluded by `.gitignore`; protect them
and do not share them as project fixtures. Existing SHA-256 password hashes
are upgraded to scrypt when the matching user next signs in. New account
passwords must be 12-128 characters. Login attempts are rate-limited in memory.

## Tests and report

Run the built-in regression suite:

```powershell
python -m unittest discover -s tests -v
```

The detailed architecture and remediation report is in
[`PROJECT_REPORT.md`](./PROJECT_REPORT.md); its PDF is
[`PROJECT_REPORT.pdf`](./PROJECT_REPORT.pdf). Rebuild the PDF after editing the
report with:

```powershell
python build_report_pdf.py
```
