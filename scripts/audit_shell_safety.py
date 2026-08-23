#!/usr/bin/env python3
"""Find shell command strings that interpolate values without quoting them.

YeepForge is migrating from `run_cmd(f'curl ... {value}')` to the HTTP engine in
utils/http.py. Until that migration finishes this audit keeps the remaining debt
visible and - via tests/test_shell_safety.py - stops it from growing.

What counts as unsafe: an f-string that looks like a shell command (it contains
`curl`, `sqlmap`, `-H `, `--cookie`, ...) and interpolates an expression that
does not go through a known quoting helper - shlex.quote, shell_quote,
_safe_url, build_curl or curl_flags. Unquoted interpolation means an
operator-supplied or target-derived value (a URL, a cookie, a payload) is parsed
by the *tester's own* shell: a `$(...)` in a cookie executes locally.

The scan is AST-based, so an f-string split across several source lines is
judged as one string rather than producing a false hit per fragment.

Usage:
    python3 scripts/audit_shell_safety.py            # count per file
    python3 scripts/audit_shell_safety.py --list     # every call site
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Helpers that make an interpolated value inert for the shell.
SAFE_CALLS = {"quote", "shell_quote", "_safe_url", "build_curl", "curl_flags"}

#: Calls whose arguments never reach a shell as a command string.
#:
#: `tool_cmd`/`shell_join` take an argument *list* and shlex-quote every element,
#: so `tool_cmd("sqlmap", [f"--cookie={cookies}"])` is safe even though the
#: fragment looks like a command line. The reporting and console helpers are here
#: for the same reason from the other direction: a finding detail quoting the
#: sqlmap output, or a menu line describing a curl command, is text for a human.
#: `remote_payload` marks a shell command aimed at the *target* - a command
#: injection probe is a shell string by definition and would otherwise be
#: indistinguishable from a local subprocess call.
SAFE_SINKS = {"tool_cmd", "shell_join", "remote_payload", "add_vuln", "add_finding",
              "print", "info", "warn", "error", "success", "section"}

#: Markers that make an f-string look like a shell command line.
SHELL_MARKERS = ("curl ", "curl -", "sqlmap ", "nuclei ", "ffuf ", "nikto ",
                 "wpscan ", "gobuster ", "feroxbuster ", "dalfox ", "-H \"",
                 "-H '", "--cookie", "--header", "--data", "-b \"")


def _is_flag_bundle(name: str) -> bool:
    """Variables that hold pre-built, already-quoted flag strings.

    `cf = _curl_flags()` and friends are assembled once and reused; auditing
    them at every use site would drown the real hits. Their *construction* is
    still audited, because building a flag with `-H "Cookie: {cookies}"` trips
    the shell markers on its own line.
    """
    return name in {"cf", "flags"} or name.endswith(("_flag", "_flags"))


def _is_safe_value(node: ast.AST) -> bool:
    """True when the interpolated expression is shell-quoted at the call site."""
    if isinstance(node, ast.Call):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        return name in SAFE_CALLS
    if isinstance(node, ast.Name):
        # ALL_CAPS names are module constants - ANSI colour codes in menu text
        # that happens to mention 'sqlmap'. Never operator or target input.
        return node.id.isupper() or _is_flag_bundle(node.id)
    # A nested f-string is judged on its own when the walker reaches it.
    return False


def _literal_text(node: ast.JoinedStr) -> str:
    return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))


def _sink_name(node: ast.Call) -> str:
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def _sheltered(tree: ast.AST) -> set[int]:
    """ids() of f-strings nested inside a call that cannot reach a shell."""
    safe = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _sink_name(node) in SAFE_SINKS:
            for child in ast.walk(node):
                if isinstance(child, ast.JoinedStr):
                    safe.add(id(child))
    return safe


def scan_file(path: Path) -> list[tuple[int, str]]:
    """Return (line_number, snippet) for each unsafe shell interpolation."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return []

    sheltered = _sheltered(tree)
    hits = []
    for node in ast.walk(tree):
        if id(node) in sheltered:
            continue
        if not isinstance(node, ast.JoinedStr):
            continue
        text = _literal_text(node)
        if not any(marker in text for marker in SHELL_MARKERS):
            continue
        # '=== curl -I {url} ===' is a section label printed into a report, not
        # a command that reaches a shell.
        if "===" in text:
            continue
        unsafe = [v for v in node.values
                  if isinstance(v, ast.FormattedValue) and not _is_safe_value(v.value)]
        for value in unsafe:
            expr = ast.unparse(value.value)
            hits.append((getattr(value, "lineno", node.lineno), f"{{{expr}}} in: {text.strip()[:90]}"))
    return sorted(set(hits))


def scan(paths: list[Path]) -> dict[str, list[tuple[int, str]]]:
    results = {}
    for path in sorted(paths):
        hits = scan_file(path)
        if hits:
            results[str(path.relative_to(ROOT))] = hits
    return results


def default_paths() -> list[Path]:
    return sorted((ROOT / "modules").rglob("*.py")) + [ROOT / "main.py"]


def total_unsafe() -> int:
    """Used by the ratchet test."""
    return sum(len(v) for v in scan(default_paths()).values())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print every call site")
    args = ap.parse_args(argv)

    results = scan(default_paths())
    total = sum(len(v) for v in results.values())
    for file, hits in sorted(results.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"{len(hits):>4}  {file}")
        if args.list:
            for num, text in hits:
                print(f"        {file}:{num}: {text}")
    print(f"\nTotal unsafe shell interpolations: {total}")
    print("Migrate these to utils.http.get_client(), or at minimum to "
          "build_curl()/curl_flags() when a shell call is still required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
