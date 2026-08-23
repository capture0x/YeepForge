"""
utils/tools.py
YeepForge - running external scanners under the engagement's rules.

sqlmap, dalfox, ffuf and friends do their own HTTP, so `utils.http` cannot pace
them, keep them inside scope, or route them through the operator's proxy. Left
alone, one of them will blow the rate limit that the rest of the run respects -
which is how a researcher gets removed from a program - and its traffic will be
missing from the Burp history the operator is reading.

This module translates the engagement into each tool's own flags:

    from utils.tools import tool_cmd
    cmd = tool_cmd("sqlmap", ["-u", url, "--batch", "--dbs"])
    run_and_print(cmd, timeout=600)

Every argument is shlex-quoted, so a payload containing `$(id)` or a cookie
containing backticks is passed to the *target* instead of being executed by the
tester's own shell.
"""
from __future__ import annotations

import os
import shlex

from config.settings import SESSION

__all__ = [
    "engagement_rps",
    "pacing_argv",
    "proxy_argv",
    "remote_payload",
    "shell_join",
    "tool_cmd",
]


def remote_payload(text: str) -> str:
    """Mark a string as a command for the *target*, not for our own shell.

    Command-injection and template-injection payloads are shell commands by
    construction - `; curl http://x/`, `$(id)` - and are indistinguishable from
    a local invocation to scripts/audit_shell_safety.py, which exists to catch
    exactly that shape. Wrapping the payload says which side of the wire it is
    for, so the audit stays strict about real subprocess calls instead of being
    taught to ignore the pattern.

    Returns the string unchanged; the value is the declaration.
    """
    return text

#: Concurrency ceiling for tools that take a worker count. Even an operator who
#: sets --rps 0 ("unlimited") gets this rather than a tool's own default of 40+,
#: because a flood that the target refuses produces no findings either way.
MAX_WORKERS = 8


def engagement_rps() -> float:
    """Requests per second allowed for this engagement. 0 means unlimited.

    Read from the same environment variable utils.http reads, so one --rps flag
    governs the Python engine and every external tool alike.
    """
    try:
        return float(os.environ.get("YEEPFORGE_RPS", "").strip() or 10.0)
    except (TypeError, ValueError):
        return 10.0


def shell_join(argv) -> str:
    """Quote an argument list into a single shell-safe command string."""
    return " ".join(shlex.quote(str(a)) for a in argv)


def pacing_argv(tool: str) -> list[str]:
    """Throttle flags expressing the engagement's rate limit in `tool`'s dialect.

    Returns an empty list for tools with no throttle of their own; those must be
    kept slow by giving them less work, not by hoping.
    """
    rps = engagement_rps()
    unlimited = rps <= 0
    # Seconds between requests, and the same figure in milliseconds.
    delay_s = 0.0 if unlimited else 1.0 / rps
    delay_ms = 50 if unlimited else max(1, int(1000 / rps))
    workers = MAX_WORKERS if unlimited else max(1, min(MAX_WORKERS, int(rps) or 1))

    if tool == "sqlmap":
        # sqlmap's --delay is seconds (float) between requests on one thread.
        return ["--threads=1", f"--delay={delay_s:.2f}"] if not unlimited else ["--threads=4"]
    if tool == "dalfox":
        return [f"--worker={workers}", "--delay", str(delay_ms)]
    if tool == "ffuf":
        return ["-rate", str(int(rps)) if not unlimited else "0", "-t", str(workers)]
    if tool == "nuclei":
        return ["-rate-limit", str(int(rps) or 1) if not unlimited else "150",
                "-concurrency", str(workers)]
    if tool == "feroxbuster":
        return ["--rate-limit", str(int(rps) or 1), "--threads", str(workers)] if not unlimited else []
    if tool == "gobuster":
        return ["--delay", f"{delay_s:.2f}s", "-t", str(workers)] if not unlimited else []
    if tool == "wpscan":
        return ["--throttle", str(delay_ms)] if not unlimited else []
    if tool == "nikto":
        return ["-Pause", f"{delay_s:.1f}"] if not unlimited else []
    if tool == "xsstrike":
        return ["--delay", str(int(delay_s) or 1)] if not unlimited else []
    return []


def proxy_argv(tool: str) -> list[str]:
    """Flags routing `tool` through the engagement proxy, if one is configured.

    An operator who sets a proxy expects the whole engagement in the proxy
    history, not just the requests that happened to go through utils.http.
    """
    proxy = (SESSION.get("proxy") or "").strip()
    if not proxy:
        return []
    if tool in ("sqlmap", "wpscan", "interactsh-client"):
        return [f"--proxy={proxy}"]
    if tool == "dalfox":
        return ["--proxy", proxy]
    if tool == "ffuf":
        return ["-x", proxy]
    if tool == "nuclei":
        return ["-proxy", proxy]
    if tool == "feroxbuster":
        return ["--proxy", proxy]
    if tool == "gobuster":
        return ["--proxy", proxy]
    if tool == "nikto":
        return ["-useproxy", proxy]
    return []


def tool_cmd(tool: str, argv, *, pace: bool = True, proxy: bool = True,
             extra: list[str] | None = None) -> str:
    """Build the full, shell-safe command line for an external scanner.

    `argv` is the tool's own arguments; pacing and proxy flags are appended so a
    caller cannot forget them. Pass pace=False only for a tool invocation that
    issues no requests to the target (a `--version` probe, a local file parse).
    """
    parts = [tool, *[str(a) for a in argv]]
    if pace:
        parts += pacing_argv(tool)
    if proxy:
        parts += proxy_argv(tool)
    if extra:
        parts += [str(e) for e in extra]
    return shell_join(parts)
