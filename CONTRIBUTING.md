# Contributing to YeepForge

Thanks for wanting to help. YeepForge is a ~13k-line offensive security tool, so
contributions are held to one standard above all others: **a module must never
turn the operator's own machine into a victim, and must never leave the
authorized scope.** Everything below follows from that.

If you found a security bug *in YeepForge itself*, stop here and read
[SECURITY.md](SECURITY.md) - do not open a public issue.

---

## Getting set up

Python **3.12+** is required. The codebase uses PEP 701 nested-quote f-strings
that do not parse on earlier versions.

```bash
git clone https://github.com/capture0x/YeepForge
cd YeepForge
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/pip install -e '.[dev]'      # pytest + ruff

cp .env.example .env                  # fill in your own values
```

Before you push anything:

```bash
venv/bin/ruff check .
venv/bin/pytest -q
```

Both must be clean. CI runs exactly these two commands on Python 3.12 and 3.13,
so a failure locally is a failure in the pull request.

---

## The rules that actually matter

### 1. All HTTP goes through `utils/http.py`

```python
from utils.http import get_client

r = get_client().get(url, params={"id": 1})
if "SQL syntax" in r.text:
    add_vuln(..., evidence=r.evidence)
```

Using the client is not a style preference. It is what guarantees, for every
single request:

- **Scope enforcement** - `utils/scope.py` checks the URL first, so a redirect
  cannot walk the scan out of the engagement
- **Rate limiting** - `--rps`, so the operator does not get banned from a bounty
  program
- **Proxy routing** - the operator's Burp history is complete
- **Evidence capture** - `r.evidence` carries the redacted request/response pair
  plus a paste-ready `curl` reproduction line, which is what makes a finding
  reportable
- **No shell** - see below

`docs/engine.md` is the full reference for writing a module against the client.

### 2. Never interpolate a value into a shell string

This is the single most dangerous pattern in this codebase:

```python
run_cmd(f"curl -H 'Cookie: {cookie}' {url}")     # NO
```

`cookie` and `url` are target-controlled. A `$(...)` in either one executes on
**the tester's machine**. YeepForge carries historical debt here - 402 call
sites as of 2026-07-25 - and it is being paid down, not added to:

```bash
venv/bin/python scripts/audit_shell_safety.py           # count per file
venv/bin/python scripts/audit_shell_safety.py --list    # every call site
```

`tests/test_shell_safety.py` freezes that count as a hard baseline. **A pull
request that raises it fails CI.** If a shell call is genuinely unavoidable, go
through `build_curl()` / `curl_flags()` / `shlex.quote` - the audit recognises
those as safe.

Migrating existing call sites to the HTTP client is one of the most useful
contributions you can make, and always welcome as a standalone PR.

### 3. Redact secrets in anything you print or write

Cookies, tokens, and API keys must not land unredacted in the terminal, a log
file, or a report. The HTTP engine handles this for captured evidence; if you
format output yourself, you own it.

### 4. Never commit engagement data

`output/`, `sast/`, generated reports, and `.env` are git-ignored because they
contain real target data and real credentials. Verify before you push:

```bash
git status --ignored
```

---

## Adding a new module

Modules follow a consistent shape - read `modules/open_redirect.py` as the
reference implementation.

1. **Create `modules/your_module.py`** with a public `run()` entry point.
   Private helpers are `_`-prefixed. Pull shared state and reporting from
   `config.settings` (`SESSION`, `OUTPUT_DIR`, `add_vuln`, `save_session`) and
   terminal output from `utils.helpers`.

2. **Register it in the main menu** - one tuple in the `MENU` structure in
   `main.py`, under the right category:

   ```python
   ("26", "Open Redirect",              "modules.open_redirect",
    "URL bypass · whitelist evasion · scheme abuse · ATO chain"),
   ```

   Dispatch is by `importlib`, so the module path string is the only wiring
   needed.

3. **Expose it to the Agent and MCP server** if it should be AI-drivable. That
   means three additions in `modules/agent/_core.py`: the tool schema, a
   `tool_<name>()` wrapper, and an entry in the dispatch dict at the bottom.
   `mcp_server.py` reads those same schemas - one source of truth, no
   duplication.

4. **Report findings through `add_vuln(...)`** with an `evidence=` payload and a
   confidence level (`Confirmed` / `Firm` / `Tentative`). A finding without
   evidence cannot be verified and should not be reported as `Confirmed`.

5. **Write a test.** `tests/test_imports.py` picks up every new module in
   `modules/` automatically and will catch import-time breakage, but detection
   logic needs its own test - see `tests/test_open_redirect.py` for the pattern
   of asserting on parsed responses rather than live traffic.

**Tests must never hit the network.** Feed the detection logic fixture
responses. A test suite that requires an internet connection, or a live target,
is not acceptable.

---

## Style

Ruff is configured in `pyproject.toml` and is the arbiter: `select = ["F", "I"]`
(pyflakes + import sorting), line length 120, target `py312`. The rule set is
deliberately narrow - the codebase has a compact one-line style in places and a
lot of long banner and payload strings, and fighting that is not the point.

Beyond what ruff enforces:

- **Match the file you are editing.** Comment density, naming, and idiom vary by
  module; consistency within a file beats global uniformity.
- **Comment the *why*, not the *what*.** The best comments in this codebase
  explain the security reasoning - why a bypass works, why a check is ordered
  the way it is. Read the module docstrings in `utils/http.py` and
  `utils/scope.py` for the tone.
- **Keep payload data out of logic.** Large payload sets belong in
  `wordlists/` or the skills directories.

---

## Pull requests

- **One concern per PR.** A new module, a shell-safety migration, and a report
  formatting fix are three pull requests.
- **Say what you tested it against.** "Verified against DVWA / Juice Shop /
  a local lab" is worth more than a description of the code. Never use a target
  you are not authorized to test - including while developing YeepForge.
- **Explain new detection logic.** What is the false-positive rate, and what
  makes a hit `Confirmed` rather than `Tentative`? A noisy module is worse than
  no module.
- **Note anything that changes the tool's blast radius** - new exploitation
  behaviour, anything that writes to or executes on a target, new outbound
  traffic. These need to be obvious to a reviewer.

Bug reports and feature requests go in GitHub issues. Include the commit hash,
your Python version, and the full traceback. Do not include target data,
hostnames, or credentials from a real engagement - sanitize first.

---

## Licence

YeepForge is MIT licensed. By contributing, you agree your contributions are
licensed under the same terms, and you confirm you have the right to submit
them.
