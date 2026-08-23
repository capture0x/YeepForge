# YeepForge as an MCP server - **no API key**

> **TL;DR - No `ANTHROPIC_API_KEY`, no local model.**
> On this path YeepForge runs **no LLM of its own**. It exposes its web-app
> pentest tools over the [Model Context Protocol](https://modelcontextprotocol.io),
> and a host that already has an LLM - **Claude Code, Cursor, Claude Desktop, …** -
> drives the engagement with its **own subscription**. The host is the brain;
> YeepForge is the toolbox.

All **28 tools** are published: the **27 scan tools** the standalone agent uses
(`recon_target`, `crawl_target`, `directory_scan`, `test_sql_injection`,
`test_xss`, `test_ssrf`, `test_xxe`, `nuclei_scan`, `analyze_source_code`,
`generate_report`, …) **plus `set_engagement`**. They use the exact schemas from
`modules/agent/_core.py` - one source of truth, no duplication.

---

## 1. Requirements

- The `mcp` Python package, plus YeepForge's normal dependencies, available to the
  **same interpreter** you launch the server with. `mcp` is in `requirements.txt`,
  so `install.sh` puts it in the project venv alongside everything else.

Verify the server can import everything and see all tools:

```bash
./venv/bin/python3 -c "import mcp; from modules.agent._core import TOOLS, TOOL_MAP; \
print('mcp ok; executable tools:', sum(1 for t in TOOLS if t['name'] in TOOL_MAP), '(+ set_engagement = 28)')"
```

If that errors, install into the venv:

```bash
./venv/bin/python3 -m pip install -r requirements.txt
```

---

## 2. Register the server

Use the path to both the interpreter and `mcp_server.py`. The server `chdir`s to
the repo root on start, so reports/loot land in `output/` and `reports/` as usual
regardless of where the host launches it. Tool status text goes to **stderr**
(the host shows it as server logs); **stdout carries only JSON-RPC**.

### Claude Code

**Option A - shipped project file (default).** The repo already contains a
`.mcp.json` at its root with repo-relative paths:

```json
{
  "mcpServers": {
    "yeepforge": {
      "command": "venv/bin/python3",
      "args": ["mcp_server.py"]
    }
  }
}
```

Because the paths are relative, this works as-is **when you launch Claude Code
from the YeepForge folder**. No edit needed - just approve the server on first
launch. If your venv lives elsewhere, point `command` at that interpreter.

**Option B - global registration via CLI** (works from any directory; use
absolute paths):

```bash
claude mcp add yeepforge -- /path/to/YeepForge/venv/bin/python3 /path/to/YeepForge/mcp_server.py
```

Confirm it registered and the tools are listed:

```bash
claude mcp list
```

### Cursor

Add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "yeepforge": {
      "command": "/path/to/YeepForge/venv/bin/python3",
      "args": ["/path/to/YeepForge/mcp_server.py"]
    }
  }
}
```

### Claude Desktop

Add to the config file
(`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows), then restart the app:

```json
{
  "mcpServers": {
    "yeepforge": {
      "command": "/path/to/YeepForge/venv/bin/python3",
      "args": ["/path/to/YeepForge/mcp_server.py"]
    }
  }
}
```

All three hosts use the same `command` + `args` shape.

---

## 3. Usage

0. **Start the host from the YeepForge folder.** With Claude Code, a project
   `.mcp.json` is only loaded when `claude` launches from the directory that
   contains it:

   ```bash
   cd /path/to/YeepForge
   claude
   ```

   Approve the `yeepforge` server on first launch, then confirm with `/mcp` (or
   `claude mcp list`). Cursor and Claude Desktop pick the server up after a
   restart. (Skip this step if you registered the server globally.)

1. **Set the engagement once.** Ask the host to call `set_engagement` with the
   target (and any auth/scope context):

   > set_engagement: target_url `https://app.example.com`, cookies
   > `sessionid=…`, proxy `http://127.0.0.1:8080`

   Required: `target_url`. Optional: `scope`, `cookies`, `headers`,
   `auth_token`, `username`, `password`, `proxy`, `engagement`, `sast_target`.

   YeepForge stores these in the session and **injects them into every later tool
   call** (`_sanitize_tool_inputs`): the target URL fills any tool's `url`/`host`,
   and cookies/proxy ride along automatically - so the model never repeats the
   target and can't accidentally hit the wrong host. Switching to a new host
   clears the previous engagement's findings.

2. **Let the host drive.** From there the host LLM reads each tool's output and
   chooses the next tool - recon → crawl → directory scan → the matching
   injection test → `generate_report` - just like the built-in agent loop, but
   funded by the host subscription.

A typical opening, in plain language to the host:

> Set the engagement to `https://app.example.com` with cookie `sessionid=…`,
> recon and crawl it, then test the discovered parameters for SQLi and XSS and
> write up a report.

---

## 4. The 28 tools at a glance

`set_engagement` (session/target) + the 27 scan tools, grouped:

| Phase | Tools |
|---|---|
| Recon | `recon_target`, `crawl_target`, `directory_scan`, `find_sensitive_files`, `check_security_headers`, `check_ssl_tls` |
| Injection | `test_sql_injection`, `test_xss`, `test_ssti`, `test_command_injection`, `test_path_traversal`, `test_xxe` |
| Web logic | `test_ssrf`, `test_cors`, `test_open_redirect`, `test_file_upload`, `test_authentication`, `test_graphql` |
| Scanning / fuzzing | `scan_vulnerabilities`, `nuclei_scan`, `fuzz_parameters`, `exploit_vulnerability` |
| Source / intel | `analyze_source_code`, `web_search` |
| Reporting | `report_finding`, `generate_report`, `finish_assessment` |

The authoritative list (names, descriptions, input schemas) is always
`modules/agent/_core.py` → `TOOLS` / `TOOL_MAP`.

---

## 5. Notes

- This path does **not** start YeepForge's own agent loop; it never imports an
  Anthropic client. The standalone `python3 main.py` agent is unchanged and still
  available.
- Tools shell out to `curl`/`nuclei`/`sslscan`/… and run blocking; each call is
  offloaded to a worker thread so the protocol stays responsive.
- Only `target_url` is required for `set_engagement`; the rest is optional auth
  and scope context.
- **Authorized use only.** The host LLM can chain real web-attack primitives
  against whatever you point it at - only run against systems you have explicit
  written permission to test.
