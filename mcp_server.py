#!/usr/bin/env python3
"""
YeepForge MCP server - exposes YeepForge's web-app pentest tools over the Model
Context Protocol so a host (Claude Code, Cursor, Claude Desktop, ...) drives the
engagement with its OWN subscription. On this path YeepForge runs no LLM of its
own and needs no Anthropic API key: the host is the brain, YeepForge is the
toolbox.

The host LLM supplies only tool-specific arguments. YeepForge injects the
authoritative target (and session cookies/proxy/auth) from the session - set
once via the `set_engagement` tool - into every subsequent call (see
_sanitize_tool_inputs), so the model never has to repeat the target URL. Fully
target-agnostic.

Launch (the venv interpreter has both `mcp` and YeepForge's deps):
    venv/bin/python3 mcp_server.py     # speaks JSON-RPC over stdio

Register in Claude Code (.mcp.json) - see docs/mcp.md.
"""
import contextlib
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
# A host may launch us from any cwd. Some tool command strings and output paths
# are cwd-relative (e.g. "output/...", wordlists/), so anchor to the repo root
# the way the standalone agent runs - keeps reports/loot in the expected place.
os.chdir(_ROOT)

# YeepForge tool code prints colorful status to stdout, but an MCP stdio server
# speaks JSON-RPC over stdout - any stray byte corrupts the protocol. Keep
# import-time chatter off the protocol stream (restored after the import), then
# at runtime route every print() to stderr. stdio_server() binds the *real*
# stdout it captures at context entry, so reassigning sys.stdout afterwards only
# affects subsequent print() calls, never the protocol.
with contextlib.redirect_stdout(sys.stderr):
    # Same SESSION dict the tools read for target_url / cookies / proxy / auth.
    from config.settings import SESSION, save_session
    from modules.agent._core import TOOL_MAP, TOOLS, _execute_tool

import anyio
import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

server = Server("yeepforge")

_SET_ENGAGEMENT = types.Tool(
    name="set_engagement",
    description=(
        "Set the engagement target and session context ONCE before running any "
        "scan tool. YeepForge injects the target URL (plus cookies/proxy/auth) "
        "into every later tool call, so you never pass the URL again. Only "
        "`target_url` is required; everything else is optional auth/scope context."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "target_url":  {"type": "string", "description": "Base target URL, e.g. https://app.example.com"},
            "scope":       {"type": "string", "description": "In-scope hosts/paths (free text), for your own reference"},
            "cookies":     {"type": "string", "description": "Session cookies, e.g. 'sessionid=abc; csrftoken=xyz' (injected into every request)"},
            "headers":     {"type": "string", "description": "Extra HTTP headers to send (optional)"},
            "auth_token":  {"type": "string", "description": "Authorization header value, e.g. 'Bearer eyJ...' (optional)"},
            "username":    {"type": "string", "description": "App username for auth tests (optional)"},
            "password":    {"type": "string", "description": "App password for auth tests (optional)"},
            "proxy":       {"type": "string", "description": "HTTP proxy, e.g. http://127.0.0.1:8080 (optional)"},
            "engagement":  {"type": "string", "description": "Engagement name for reports (optional)"},
            "sast_target": {"type": "string", "description": "Local source-code path for analyze_source_code (optional)"},
        },
        "required": ["target_url"],
    },
)

# Engagement-context keys set_engagement is allowed to write into SESSION.
_ENGAGEMENT_KEYS = (
    "target_url", "scope", "cookies", "headers", "auth_token",
    "username", "password", "proxy", "engagement", "sast_target",
)

# Per-engagement state wiped when the target host changes, so findings/endpoints
# from a previous target never bleed into the next report.
_PER_ENGAGEMENT_STATE = (
    "findings", "vulns_found", "endpoints", "subdomains", "tech_stack", "loot",
    "agent_endpoints", "agent_params", "agent_upload_endpoints",
)


def _host_of(url: str) -> str:
    """Bare host[:port] of a URL - what check_ssl_tls expects as `host`."""
    import re
    return re.sub(r"^https?://", "", str(url or "")).rstrip("/").split("/")[0]


@server.list_tools()
async def _list_tools():
    """Expose set_engagement plus every executable YeepForge tool, reusing the
    same schemas the standalone agent uses (single source of truth)."""
    tools = [_SET_ENGAGEMENT]
    for t in TOOLS:
        if t["name"] in TOOL_MAP:
            tools.append(
                types.Tool(
                    name=t["name"],
                    description=t.get("description", ""),
                    inputSchema=t["input_schema"],
                )
            )
    return tools


def _set_engagement(args: dict) -> str:
    target_url = str(args.get("target_url") or "").strip()
    if not target_url:
        return "set_engagement rejected: target_url is required. Session unchanged."
    if not target_url.lower().startswith(("http://", "https://")):
        target_url = "https://" + target_url

    # Switching to a different host must not carry the previous engagement's
    # findings/endpoints/loot forward into the new report.
    prev_host = _host_of(SESSION.get("target_url", ""))
    new_host = _host_of(target_url)
    if prev_host and new_host and prev_host.lower() != new_host.lower():
        for k in _PER_ENGAGEMENT_STATE:
            cur = SESSION.get(k)
            SESSION[k] = {} if isinstance(cur, dict) else []
        host_changed = True
    else:
        host_changed = False

    SESSION["target_url"] = target_url
    SESSION["target_host"] = new_host
    for k in _ENGAGEMENT_KEYS:
        if k == "target_url":
            continue
        if k in args and args.get(k) is not None:
            SESSION[k] = str(args.get(k))

    with contextlib.suppress(Exception):
        save_session()

    auth = []
    if SESSION.get("cookies"):
        auth.append("cookies")
    if SESSION.get("auth_token"):
        auth.append("auth_token")
    if SESSION.get("username"):
        auth.append("username")
    auth_s = ",".join(auth) or "none"
    proxy_s = SESSION.get("proxy") or "none"
    note = " previous target's findings cleared;" if host_changed else ""
    return (
        f"Engagement set: {target_url} (auth={auth_s}, proxy={proxy_s}).{note} "
        "Run recon_target / crawl_target next."
    )


def _sanitize_tool_inputs(name: str, args: dict) -> dict:
    """Single validation/injection authority. Inject the session target into
    tools that need it so the host never has to repeat the URL, and keep only
    keys each tool's schema declares."""
    args = dict(args or {})
    schema = next((t["input_schema"] for t in TOOLS if t["name"] == name), {})
    props = schema.get("properties", {})

    target = SESSION.get("target_url", "")
    # url-based tools: fill from session target when the host omitted it.
    if "url" in props and not str(args.get("url") or "").strip() and target:
        args["url"] = target
    # check_ssl_tls wants a bare host.
    if "host" in props and not str(args.get("host") or "").strip():
        host = SESSION.get("target_host") or _host_of(target)
        if host:
            args["host"] = host
    # analyze_source_code wants a local path; fall back to the session's.
    if "code_path" in props and not str(args.get("code_path") or "").strip():
        sast = SESSION.get("sast_target", "")
        if sast:
            args["code_path"] = sast

    # Drop keys the tool doesn't declare so a chatty host can't break the call.
    if props:
        args = {k: v for k, v in args.items() if k in props}
    return args


@server.call_tool(validate_input=False)
async def _call_tool(name: str, arguments: dict | None):
    args = arguments or {}
    if name == "set_engagement":
        return [types.TextContent(type="text", text=_set_engagement(args))]
    if name not in TOOL_MAP:
        return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    clean = _sanitize_tool_inputs(name, args)
    # Tools shell out to curl/nuclei/sslscan/etc. (blocking). Offload to a worker
    # thread so the asyncio event loop stays responsive for the protocol.
    out = await anyio.to_thread.run_sync(_execute_tool, name, clean)
    return [types.TextContent(type="text", text=str(out))]


async def _main():
    async with stdio_server() as (read_stream, write_stream):
        # Protocol streams are already bound to the real stdout; from here on send
        # all tool/print chatter to stderr so it can't corrupt JSON-RPC frames.
        sys.stdout = sys.stderr
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(_main)
