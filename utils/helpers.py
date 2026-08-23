"""
utils/helpers.py
YeepForge - UI/UX helpers, colors, print functions
"""
from __future__ import annotations

import datetime
import os
import shlex
import subprocess
import sys
import threading
import time
from typing import Any


# ── ANSI colors ───────────────────────────────────────────────────────────────
def fg(n: int) -> str:      return f"\033[38;5;{n}m"
def bg(n: int) -> str:      return f"\033[48;5;{n}m"
def fg_rgb(r, g, b) -> str: return f"\033[38;2;{r};{g};{b}m"

# YeepForge palette - modern "AI console": desaturated, low-glare, violet + teal
# Names keep their semantics (GRN=success, RED=error, YEL=warn); only tones softened.
NEON_GRN   = fg_rgb(52, 211, 153)    # emerald - success / go
NEON_CYN   = fg_rgb(45, 212, 191)    # teal - info / primary accent
NEON_RED   = fg_rgb(244, 114, 114)   # soft rose - error / critical
NEON_YEL   = fg_rgb(245, 191, 100)   # warm amber - warning
NEON_BLU   = fg_rgb(129, 161, 255)   # periwinkle - links / neutral
NEON_PUR   = fg_rgb(167, 139, 250)   # violet - the AI signature accent

WS_GREEN   = NEON_GRN
WS_CYAN    = NEON_CYN
WS_RED     = NEON_RED

R    = NEON_RED
G    = NEON_GRN
Y    = NEON_YEL
B    = NEON_CYN
C    = NEON_CYN
M    = NEON_PUR
W    = fg(255)

DIM  = "\033[2m"
BOLD = "\033[1m"
ITAL = "\033[3m"
UND  = "\033[4m"
RST  = "\033[0m"

PURE_WHITE = fg(255)
SOFT_WHITE = fg(252)
SLATE      = fg(245)
STEEL      = fg(250)

SEV_COLOR = {
    "Critical": NEON_RED + BOLD,
    "High":     fg(208) + BOLD,
    "Medium":   NEON_YEL + BOLD,
    "Low":      NEON_CYN,
    "Info":     NEON_GRN,
}

# ── Output helpers ────────────────────────────────────────────────────────────
def cprint(msg: Any, color: str = W) -> None: print(f"{color}{msg}{RST}")
def success(msg: Any) -> None:  print(f"  {NEON_GRN}[+]{RST} {msg}")
def warn(msg: Any) -> None:     print(f"  {NEON_YEL}[!]{RST} {msg}")
def info(msg: Any) -> None:     print(f"  {NEON_CYN}[*]{RST} {msg}")
def error(msg: Any) -> None:    print(f"  {NEON_RED}[-]{RST} {msg}")
def debug(msg: Any) -> None:    print(f"  {DIM}[.]{RST} {DIM}{msg}{RST}")
def critical(msg: Any) -> None: print(f"  {NEON_RED}{BOLD}[!!]{RST} {NEON_RED}{BOLD}{msg}{RST}")

class NonInteractive(Exception):
    """Raised when a prompt has no answer available and no usable default.

    Module submenus are `while True` loops driven by prompt(); returning a blank
    string to one of those spins forever. Raising instead unwinds out of the
    loop and is caught once, at the dispatcher."""


def prompt(msg: Any, default: str | None = None) -> str:
    """Ask the user for a line of input.

    Every module submenu funnels through here, so a bare input() made the whole
    framework unusable outside an interactive terminal: piping anything into
    main.py (`--module A`, CI, scripts) blew up with an EOFError traceback.

    Resolution order: honour YEEPFORGE_NONINTERACTIVE, fall back to /dev/tty
    when stdin is redirected but a terminal still exists, then treat EOF/Ctrl-C
    as "no answer". With no answer, callers that supplied a `default` get it;
    callers that did not get NonInteractive so their loop unwinds."""
    def _unanswered() -> str:
        if default is not None:
            return default
        raise NonInteractive(f"no input available for prompt: {msg}")

    if os.environ.get("YEEPFORGE_NONINTERACTIVE") == "1":
        return _unanswered()
    try:
        if not sys.stdin.isatty():
            try:
                sys.stdin = open("/dev/tty")
            except OSError:
                return _unanswered()
        raw = input(f"  {NEON_GRN}[?]{RST} {msg}: ").strip()
    except (EOFError, KeyboardInterrupt, OSError):
        print()
        return _unanswered()
    # A blank line at a live terminal is a deliberate "use the default".
    return raw if raw else (default if default is not None else "")


def confirm(msg: Any, default: bool = False) -> bool:
    """Yes/no gate. Anything other than an explicit y/yes is a no, so an
    unanswered prompt fails safe (declines) rather than proceeding."""
    suffix = "[Y/n]" if default else "[y/N]"
    raw = prompt(f"{msg} {suffix}", default="y" if default else "n").lower()
    return raw in ("y", "yes")

def ask_int(label: str, default: int,
            minimum: int | None = None, maximum: int | None = None) -> int:
    """Prompt for a whole number. Blank input keeps `default`; non-numeric input
    warns and falls back to `default` instead of crashing; the result is clamped
    to [minimum, maximum] when those are given. Never raises."""
    raw = prompt(f"{label} [{default}]", default=str(default))
    if not raw:
        return default
    try:
        val = int(raw)
    except ValueError:
        warn(f"'{raw}' is not a whole number - using {default}")
        return default
    if minimum is not None and val < minimum:
        val = minimum
    if maximum is not None and val > maximum:
        val = maximum
    return val

def pause(msg: str = "[Enter] to return") -> None:
    try:
        if not sys.stdin.isatty():
            sys.stdin = open("/dev/tty")
        input(f"\n  {NEON_GRN}[↵]{RST} {msg} ")
    except Exception:
        pass

def shell_quote(value: Any) -> str:
    return shlex.quote("" if value is None else str(value))

def _strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)

# ── Banner / section ──────────────────────────────────────────────────────────
def print_banner(title: str, sub: str = "") -> None:
    sep = f"{WS_GREEN}{'═' * 68}{RST}"
    print(f"\n{sep}")
    print(f"  {WS_GREEN}{BOLD}{title}{RST}")
    if sub:
        print(f"  {SOFT_WHITE}{sub}{RST}")
    print(sep + "\n")

def section(title: str) -> None:
    print(f"\n  {WS_CYAN}{BOLD}── {title} {'─' * max(0, 60 - len(title))}{RST}")

# ── Table printer ─────────────────────────────────────────────────────────────
def print_table(headers: list, rows: list, caption: str = "") -> None:
    if caption:
        print(f"\n  {WS_CYAN}{caption}{RST}")
    if not rows:
        print(f"  {DIM}(no data){RST}")
        return
    widths = [len(h) for h in headers]
    str_rows = []
    for row in rows:
        srow = [_strip_ansi(str(c)) for c in row]
        str_rows.append(srow)
        for i, c in enumerate(srow):
            if i < len(widths):
                widths[i] = max(widths[i], len(c))
    sep = "  " + "─" * (sum(widths) + 3 * len(headers) + 1)
    header_line = "  │ " + " │ ".join(
        f"{WS_CYAN}{BOLD}{h:<{widths[i]}}{RST}" for i, h in enumerate(headers)
    ) + " │"
    print(sep)
    print(header_line)
    print(sep)
    for orig_row, srow in zip(rows, str_rows):
        cells = []
        for i, (orig_c, sc) in enumerate(zip(orig_row, srow)):
            pad = widths[i] - len(sc)
            cells.append(str(orig_c) + " " * pad)
        print("  │ " + " │ ".join(cells) + " │")
    print(sep)

# ── Spinner ───────────────────────────────────────────────────────────────────
def spinner(msg: str, stop_event: threading.Event) -> None:
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r  {WS_GREEN}{frames[i % len(frames)]}{RST}  {msg}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write("\r" + " " * (len(msg) + 10) + "\r")
    sys.stdout.flush()

def run_spinner(msg: str, fn, *args, **kwargs):
    stop = threading.Event()
    t = threading.Thread(target=spinner, args=(msg, stop), daemon=True)
    t.start()
    try:
        result = fn(*args, **kwargs)
    finally:
        stop.set()
        t.join()
    return result

# ── Command runner ────────────────────────────────────────────────────────────
def run_cmd(cmd: str, timeout: int = 120, shell: bool = True) -> tuple[str, str, int]:
    try:
        proc = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:
        return "", str(e), 1

def run_and_print(cmd: str, timeout: int = 120) -> str:
    info(f"Running: {DIM}{cmd}{RST}")
    out, err, rc = run_cmd(cmd, timeout=timeout)
    if out:
        print(out)
    if err and rc != 0:
        print(f"{NEON_RED}{err}{RST}")
    return out

# ── Finding tracker ───────────────────────────────────────────────────────────
def add_finding(session: dict, title: str, severity: str = "Medium",
                detail: str = "", owasp: str = "", evidence: Any = None,
                confidence: str = "Firm", url: str = "") -> None:
    """Record a finding, ideally with the request/response that proves it.

    Pass `response.evidence` from utils.http as `evidence`; it is normalised to
    a plain dict (secrets already redacted) so reports and session JSON stay
    serialisable.
    """
    from config.settings import normalize_evidence  # local: helpers must stay import-light
    ev = normalize_evidence(evidence)
    session.setdefault("findings", []).append({
        "title":      title,
        "severity":   severity,
        "detail":     detail,
        "owasp":      owasp,
        "url":        url,
        "confidence": confidence,
        "evidence":   ev,
        "time":       datetime.datetime.now().isoformat(),
    })
    sev_c = SEV_COLOR.get(severity, NEON_YEL)
    proof = f" {DIM}[evidence]{RST}" if ev else ""
    print(f"  {NEON_GRN}[FINDING]{RST} {sev_c}{severity}{RST}  {BOLD}{title}{RST}{proof}")
    if owasp:
        print(f"           {DIM}{owasp}{RST}")
