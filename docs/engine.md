# The request engine - scope, rate limiting, evidence

Every request YeepForge makes should go through `utils/http.py`. This document
explains what that buys you and how to use it.

## Why

YeepForge historically issued requests by shelling out to `curl` with a
per-call-site f-string. Four things were impossible to guarantee that way:

| Problem | Consequence |
|---|---|
| Proxy applied per call site | Burp history was incomplete - evidence lost |
| No rate limiting | Bounty programs ban researchers who hammer them |
| No captured request/response | Findings were unreportable and unverifiable |
| Values interpolated into a shell string | A `$(...)` in a cookie ran on **your** machine |

## Using it

```python
from utils.http import get_client
from config.settings import add_vuln

client = get_client()          # shared: one rate budget, one history per run
r = client.get("/item", params={"id": "1'"})   # relative paths resolve against the target

if "SQL syntax" in r.text:
    add_vuln("SQL Injection", "Critical", "A03:2021",
             "Error-based SQLi", r.url,
             evidence=r.evidence, confidence="Confirmed", cwe="CWE-89")
```

`r.evidence` holds the redacted request/response pair, the round-trip time and a
ready-to-paste `curl` reproduction line. The reporter renders it verbatim in
both HTML and Markdown, which is what makes a finding acceptable to a client or
a bounty triager.

`client.safe_get(url)` returns `None` instead of raising - convenient in bulk
probing loops.

## Scope

Requests are checked against the engagement scope before they leave the
machine. Scope is written the way programs publish it:

```
*.example.com
api.example.com
!admin.example.com
```

With no explicit scope, it is derived from the target host **and its
subdomains** - a tool pointed at one host will not silently scan another. An
out-of-scope request raises `ScopeViolation`.

```bash
./run.sh --target https://example.com --scope '*.example.com,!admin.example.com'
./run.sh --target https://example.com --scope-audit    # report, don't block
```

## Configuration

Set on the CLI, or in the environment for the MCP server and agent paths:

| Variable | CLI flag | Default | Meaning |
|---|---|---|---|
| `YEEPFORGE_RPS` | `--rps` | 10 | Requests per second; 0 = unlimited |
| `YEEPFORGE_TIMEOUT` | - | 15 | Per-request timeout (seconds) |
| `YEEPFORGE_RETRIES` | - | 2 | Retries on connection error / 429 / 5xx |
| `YEEPFORGE_JITTER` | - | 0 | Extra random delay per request (seconds) |
| `YEEPFORGE_UA` | - | Chrome-like | User-Agent override |
| `YEEPFORGE_VERIFY_TLS` | - | off | Turn certificate validation back on |
| `YEEPFORGE_SCOPE` | `--scope-audit` | enforce | `audit`/`off` warns instead of blocking |
| `YEEPFORGE_SHOW_SECRETS` | - | off | Keep auth headers in evidence and session file |

The proxy comes from the session (`--proxy`, `.env` `PROXY=`) and is applied to
**every** request, so Burp sees the full engagement.

## Confidence

`add_vuln(..., confidence=...)` takes `Confirmed`, `Firm` or `Tentative`. Use
`Confirmed` only when the response proves it (command output echoed, template
expression evaluated, database error returned). Time-based detections are at
most `Firm`: they compare against a measured baseline, not a fixed threshold,
but latency is still circumstantial.

## Still shelling out?

Some tooling has no library equivalent (sqlmap, nuclei, ffuf). When a shell
command is unavoidable, never interpolate raw values:

```python
from utils.http import build_curl, curl_flags

cmd = build_curl(url, method="POST", data=payload)   # every value shlex-quoted
out, _, _ = run_cmd(cmd)

# or, keeping an existing command string but gaining proxy/cookies/auth safely:
run_cmd(f"curl {curl_flags()} {shlex.quote(url)}")
```

`scripts/audit_shell_safety.py` lists the call sites that still interpolate
unquoted values, and `tests/test_shell_safety.py` fails if that count grows.
Lower the baseline as you migrate.
