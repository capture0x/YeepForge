#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  YeepForge - Professional Web Application Pentest Framework          ║
║  OWASP Top 10 · AI Agent · Authorized Engagements Only               ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
import importlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import SESSION, load_session, save_session
from utils.helpers import (
    BOLD,
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_PUR,
    NEON_RED,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    NonInteractive,
    _strip_ansi,
    error,
    fg_rgb,
    info,
    print_table,
    prompt,
    success,
    warn,
)

VERSION  = "1.0"
CODENAME = "YeepForge"
AUTHOR   = "capture0x - powered by tmrswrr"
BUILD    = "2026.05"

_G = NEON_GRN
_C = NEON_CYN

_ART = r"""
__   __              _____
\ \ / /__  ___ _ __ |  ___|__  _ __ __ _  ___
 \ V / _ \/ _ \ '_ \| |_ / _ \| '__/ _` |/ _ \
  | |  __/  __/ |_) |  _| (_) | | | (_| |  __/
  |_|\___|\___| .__/|_|  \___/|_|  \__, |\___|
              |_|                  |___/
"""


def _render_banner() -> str:
    palette = [NEON_PUR, NEON_CYN]
    out = []
    for i, line in enumerate(ln for ln in _ART.splitlines() if ln.strip()):
        color = palette[i % len(palette)]
        out.append(f"  {color}{BOLD}{line}{RST}")
    return "\n".join(out)


def _chip(label: str, color: str) -> str:
    """A soft dot-led status chip."""
    return f"{color}●{RST} {SOFT_WHITE}{label}{RST}"


def _tagline() -> str:
    row1 = (
        f"  {NEON_CYN}{BOLD}WEB·APPLICATION·FORGE{RST}   "
        f"{_chip(f'v{VERSION}', NEON_GRN)}    "
        f"{_chip('OWASP 10', NEON_RED)}    "
        f"{_chip('40+ modules', NEON_CYN)}    "
        f"{_chip('AI agent', NEON_PUR)}"
    )
    row2 = (
        f"  {DIM}build {BUILD}  ·  authorised penetration testing only{RST}"
    )
    return f"{row1}\n{row2}"


def _clear():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


SHOW_BANNER = True

def show_banner(clear: bool = True):
    if not SHOW_BANNER:
        return
    if clear:
        _clear()
    print()
    print(_render_banner())
    print(_tagline())
    print()


# ── Menu registry ─────────────────────────────────────────────────────────────
OWASP_PHASES = [
    ("AUTOMATED", NEON_GRN, [
        ("A",  "Auto Full Scan",             "modules.auto_scanner",         "one-click OWASP scan · crawl → test → nikto → nuclei → report"),
        ("C",  "Web Crawler",                "modules.crawler",              "link/form/JS/API endpoint discovery"),
        ("W",  "WAF Detection & Bypass",     "modules.waf_bypass",           "fingerprint 14+ WAFs · bypass payloads · rate limit evasion"),
        ("O",  "OOB Callback Server",        "modules.oob_server",           "blind SSRF/XXE/CMDi/SQLi · Log4Shell · local HTTP listener"),
    ]),
    ("RECONNAISSANCE", NEON_CYN, [
        ("1",  "Recon & Enumeration",        "modules.recon",                "subdomains · dirbusting · fingerprint · ports"),
    ]),
    ("OWASP A01 - BROKEN ACCESS CONTROL", NEON_RED, [
        ("2",  "Broken Access Control",       "modules.broken_access_control","IDOR · path traversal · admin paths · JWT"),
    ]),
    ("OWASP A02 - CRYPTOGRAPHIC FAILURES", NEON_GRN, [
        ("3",  "Cryptographic Failures",      "modules.crypto_failures",      "cleartext · sensitive files · weak hashes · JS secrets"),
    ]),
    ("OWASP A03 - INJECTION", NEON_RED, [
        ("4",  "Injection Attacks",           "modules.injection",            "SQLi · XSS · SSTI · CMDi · XXE · NoSQL · LDAP"),
    ]),
    ("OWASP A04 - INSECURE DESIGN", NEON_GRN, [
        ("5",  "Insecure Design",             "modules.insecure_design",      "business logic · race conditions · mass assignment"),
    ]),
    ("OWASP A05 - SECURITY MISCONFIGURATION", NEON_RED, [
        ("6",  "Security Misconfiguration",   "modules.security_misconfig",   "headers · CORS · debug endpoints · default creds · SSL"),
    ]),
    ("OWASP A06 - VULNERABLE COMPONENTS", NEON_GRN, [
        ("7",  "Vulnerable Components",       "modules.vulnerable_components","CVE scan · nikto · CMS scanner · Log4Shell · JS deps"),
    ]),
    ("OWASP A07 - AUTHENTICATION FAILURES", NEON_RED, [
        ("8",  "Authentication Failures",     "modules.auth_failures",        "brute force · credential stuffing · session · MFA bypass"),
    ]),
    ("OWASP A08 - INTEGRITY FAILURES", NEON_GRN, [
        ("9",  "Software Integrity Failures", "modules.integrity_failures",   "deserialization · SRI · CI/CD exposure"),
    ]),
    ("OWASP A09 - LOGGING FAILURES", NEON_RED, [
        ("10", "Logging & Monitoring",        "modules.logging_failures",     "log injection · error exposure · detection gaps"),
    ]),
    ("OWASP A10 - SSRF", NEON_GRN, [
        ("11", "Server-Side Request Forgery", "modules.ssrf",                 "internal ports · cloud metadata · gopher · blind SSRF"),
    ]),
    ("SAST - STATIC APPLICATION SECURITY TESTING", NEON_CYN, [
        ("12", "SAST Code Analysis",         "modules.sast",
         "Architecture · SQLi · XSS · RCE · SSRF · JWT · IDOR · 15 skills · AI"),
    ]),
    ("ADVANCED EXPLOITATION TECHNIQUES", NEON_YEL, [
        ("17", "HTTP Request Smuggling",     "modules.http_smuggling",
         "CL.TE · TE.CL · TE Obfuscation · H2.TE downgrade"),
        ("18", "OAuth / SAML / OIDC",        "modules.oauth_saml",
         "Redirect URI bypass · state CSRF · implicit flow · SAML XSW/XXE"),
        ("19", "WebSocket Security",         "modules.websocket_security",
         "CSWSH · message injection · origin bypass · cleartext"),
        ("20", "Cache Poisoning / Deception","modules.cache_poisoning",
         "Unkeyed headers · fat GET · cache deception · DoS"),
        ("21", "API Security",               "modules.api_security",
         "GraphQL introspection · batch abuse · REST enum · mass assignment"),
    ]),
    ("WEB APPLICATION ATTACKS", NEON_GRN, [
        ("26", "Open Redirect",              "modules.open_redirect",
         "URL bypass · whitelist evasion · scheme abuse · ATO chain"),
        ("27", "Clickjacking / UI Redressing","modules.clickjacking",
         "Frame detection · PoC generator · sandbox bypass · multi-step"),
        ("28", "CRLF Injection",             "modules.crlf_injection",
         "Header injection · response splitting · XSS · log injection"),
        ("29", "Subdomain Takeover",         "modules.subdomain_takeover",
         "25 service fingerprints · CNAME hijack · nuclei scan"),
        ("30", "Account Takeover",           "modules.account_takeover",
         "Password reset · email change · 2FA bypass · enumeration"),
        ("31", "Advanced File Upload",       "modules.file_upload_advanced",
         "Extension bypass · polyglot · SVG XSS · ZIP slip · ImageMagick"),
        ("37", "CSRF",                       "modules.csrf",
         "Token detection · bypass · PoC generator · SameSite analysis"),
        ("38", "HTTP Verb Tampering",        "modules.http_verb_tampering",
         "PUT/DELETE/TRACE · XST · method override · file write"),
        ("39", "Prototype Pollution",        "modules.prototype_pollution",
         "JS __proto__ · PHP type juggling · XPath · email header injection"),
        ("32", "HTTP Parameter Pollution",   "modules.http_parameter_pollution",
         "WAF bypass · business logic · client-side HPP"),
        ("40", "LFI / RFI / PHP Wrappers",  "modules.lfi_rfi",
         "LFI 18 payloads · php://filter source read · log poisoning RCE · RFI"),
        ("41", "Webshells",                  "modules.webshells",
         "PHP/ASPX/JSP generate · interact · obfuscate · reverse shell"),
        ("42", "Session Security",           "modules.session_security",
         "Cookie attrs · fixation · timeout · logout · cache · exposed vars"),
        ("43", "XXE Injection",              "modules.xxe_injection",
         "Classic · Error-based · Blind OOB · SSRF · SVG/Office · PHP filter · WAF bypass"),
        ("44", "Race Conditions & IDOR",    "modules.race_idor",
         "Parallel race attacks · IDOR enumeration · business logic · 2FA bypass · account enum"),
        ("45", "Passive Recon (OSINT)",     "modules.recon_passive",
         "WHOIS · DNS · subdomains · Google dorks · GitHub leaks · Shodan · email harvest"),
    ]),
]

UTILITIES = [
    ("33", "YeepForge Agent (AI)",  "modules.agent",   "Claude AI · Ollama · autonomous OWASP scan · tool loop"),
    ("34", "Generate Report",       "modules.reporting","HTML · Markdown · JSON pentest report"),
    ("35", "Session Manager",       None,               "Save · load · view · clear session"),
    ("36", "Tool Checker",          None,               "Verify installed security tools"),
    ("0",  "Exit",                  None,               "Save session & quit"),
]

# Build flat dispatch table
MODULES: dict = {}
for _, _, items in OWASP_PHASES:
    for key, name, mod_path, _ in items:
        MODULES[key] = (name, mod_path)
for key, name, mod_path, _ in UTILITIES:
    MODULES[key] = (name, mod_path)


def _choice_sort_key(key: str) -> tuple:
    """Digits first in numeric order, then the letter shortcuts."""
    return (0, int(key), "") if key.isdigit() else (1, 0, key)


def valid_choices() -> list:
    return sorted(MODULES, key=_choice_sort_key)


# ── Dashboard ─────────────────────────────────────────────────────────────────
def _dashboard():
    target   = SESSION.get("target_url", "") or f"{DIM}-{RST}"
    eng      = SESSION.get("engagement", "") or f"{DIM}-{RST}"
    cookies  = "SET" if SESSION.get("cookies") else "none"
    proxy    = SESSION.get("proxy", "") or "none"
    findings = len(SESSION.get("findings", [])) + len(SESSION.get("vulns_found", []))
    vulns    = len([f for f in SESSION.get("vulns_found", [])
                    if f.get("severity") in ("Critical", "High")])

    import shutil as _sh
    cols = _sh.get_terminal_size((100, 24)).columns
    W = max(60, min(96, cols - 4))
    frame = NEON_GRN

    top = f"{frame}┌{'─'*W}┐{RST}"
    bot = f"{frame}└{'─'*W}┘{RST}"

    def row(content):
        vis = _strip_ansi(content)
        pad = max(W - 2 - len(vis), 0)
        return f"{frame}│{RST}  {content}{' '*pad}{frame}│{RST}"

    r1 = (
        f"{NEON_CYN}{BOLD}TARGET{RST}  {PURE_WHITE}{target}{RST}"
        f"  {DIM}|{RST}  "
        f"{NEON_CYN}{BOLD}ENGAGE{RST}  {PURE_WHITE}{eng}{RST}"
    )
    sast_target = SESSION.get("sast_target", "")
    sast_short  = os.path.basename(sast_target) if sast_target else "-"
    r2 = (
        f"{NEON_CYN}{BOLD}COOKIES{RST}  {NEON_GRN if cookies=='SET' else DIM}{cookies}{RST}"
        f"  {DIM}|{RST}  "
        f"{NEON_CYN}{BOLD}PROXY{RST}  {SOFT_WHITE}{proxy}{RST}"
        f"  {DIM}|{RST}  "
        f"{NEON_CYN}{BOLD}FINDINGS{RST}  {PURE_WHITE}{BOLD}{findings}{RST}{SOFT_WHITE} ({vulns} crit/high){RST}"
    )
    r3 = (
        f"{NEON_CYN}{BOLD}SAST CODE{RST}  {PURE_WHITE}{sast_short}{RST}"
    )

    print(top)
    print(row(r1))
    print(row(r2))
    print(row(r3))
    print(bot)


# ── Modern deck-grid menu ─────────────────────────────────────────────────────
def _visw(s: str) -> int:
    """Visible width of a string, ignoring ANSI escapes."""
    return len(_strip_ansi(s))


# Visual grouping (presentation only - dispatch still flows through MODULES).
# Each deck: (title, accent, glyph). Phases are routed into decks by name.
_DECK_ORDER = [
    ("ATTACK SURFACE",   NEON_GRN, "◆"),
    ("OWASP TOP 10",     NEON_RED, "❖"),
    ("ADVANCED VECTORS", NEON_YEL, "✦"),
    ("WEB ATTACK ARSENAL", NEON_CYN, "✷"),
    ("CODE · INTELLIGENCE", NEON_PUR, "◈"),
]

# Short badges + display names for the console footer row.
_UTIL_SHORT = {
    "33": "Agent", "34": "Report", "35": "Session", "36": "Tools", "0": "Exit",
}


def _phase_deck(phase_name: str) -> tuple[str, str]:
    """Map an OWASP_PHASES entry to (deck_title, badge)."""
    if phase_name.startswith("OWASP A"):
        return "OWASP TOP 10", phase_name.split()[1]        # e.g. "A03"
    if phase_name == "AUTOMATED":
        return "ATTACK SURFACE", "auto"
    if phase_name == "RECONNAISSANCE":
        return "ATTACK SURFACE", "recon"
    if phase_name.startswith("ADVANCED"):
        return "ADVANCED VECTORS", ""
    if phase_name.startswith("WEB APPLICATION"):
        return "WEB ATTACK ARSENAL", ""
    if phase_name.startswith("SAST"):
        return "CODE · INTELLIGENCE", "sast"
    return "CODE · INTELLIGENCE", ""


def _build_decks() -> dict:
    """Bucket OWASP_PHASES items into presentation decks: title -> [(key, name, badge)]."""
    decks: dict = {title: [] for title, _, _ in _DECK_ORDER}
    for phase_name, _color, items in OWASP_PHASES:
        title, badge = _phase_deck(phase_name)
        for key, name, _mod, _desc in items:
            decks.setdefault(title, []).append((key, name, badge))
    # Fold the AI Agent + Report utilities into the intelligence deck.
    decks["CODE · INTELLIGENCE"].append(("33", "YeepForge Agent", "ai"))
    decks["CODE · INTELLIGENCE"].append(("34", "Generate Report", "out"))
    return decks


def _cell(key: str, name: str, w: int) -> str:
    """Render one grid cell: right-aligned key, then name, padded to `w` columns."""
    name_max = max(6, w - 6)
    if len(name) > name_max:
        name = name[:name_max - 1] + "…"
    left = f"{NEON_CYN}{BOLD}{key:>2}{RST}   {SOFT_WHITE}{name}{RST}"
    return left + " " * max(1, w - _visw(left))


# Violet → teal, the AI-console signature gradient used for section tick bars.
_GRAD_A = (167, 139, 250)   # violet
_GRAD_B = (45, 212, 191)    # teal


def _grad(i: int, n: int) -> str:
    """Colour at position i of n along the violet→teal gradient."""
    t = 0.0 if n <= 1 else i / (n - 1)
    r = round(_GRAD_A[0] + (_GRAD_B[0] - _GRAD_A[0]) * t)
    g = round(_GRAD_A[1] + (_GRAD_B[1] - _GRAD_A[1]) * t)
    b = round(_GRAD_A[2] + (_GRAD_B[2] - _GRAD_A[2]) * t)
    return fg_rgb(r, g, b)


def _deck_header(title: str, accent: str) -> str:
    """A calm section header: a colored tick bar + white title."""
    return f"  {accent}{BOLD}▍{RST} {PURE_WHITE}{BOLD}{title}{RST}"


def print_menu():
    import shutil as _sh
    show_banner()
    _dashboard()
    print()

    cols_term = _sh.get_terminal_size((100, 24)).columns
    W      = max(76, min(96, cols_term - 2))
    cols   = 2 if W >= 88 else 1
    indent = 5
    gutter = 4
    cell_w = ((W - indent) - gutter * (cols - 1)) // cols

    decks = _build_decks()

    # Assemble the sections to render: decks (in order) + the console footer.
    console = [(k, _UTIL_SHORT.get(k, n))
               for k, n, _m, _d in UTILITIES if k in ("35", "36", "0")]
    sections = [(title, [(k, n) for k, n, _b in decks.get(title, [])])
                for title, _a, _g in _DECK_ORDER if decks.get(title)]
    sections.append(("CONSOLE", console))

    # Colour each section tick bar along one violet→teal gradient.
    for idx, (title, items) in enumerate(sections):
        print(_deck_header(title, _grad(idx, len(sections))))
        cells = [_cell(k, n, cell_w) for k, n in items]
        for i in range(0, len(cells), cols):
            print(" " * indent + (" " * gutter).join(cells[i:i + cols]))
        print()


# ── Session setup ─────────────────────────────────────────────────────────────
def session_setup():
    if SESSION.get("target_url"):
        info(f"Session loaded - target: {NEON_CYN}{SESSION['target_url']}{RST}")
        _arm_session_monitor()
        return

    print()
    print(f"  {NEON_GRN}{BOLD}SESSION SETUP{RST}  {SOFT_WHITE}Configure your engagement (Enter to skip){RST}")
    print(f"  {NEON_GRN}{'─'*60}{RST}")
    print()

    fields = [
        ("target_url",  "Target URL (e.g. https://example.com)"),
        ("engagement",  "Engagement Name"),
        ("scope",       "In-scope hosts (*.example.com, !admin.example.com)"),
        ("cookies",     "Session Cookies (name=value; name2=value2)"),
        ("auth_token",  "Authorization Token (Bearer ...)"),
        ("proxy",       "HTTP Proxy (e.g. http://127.0.0.1:8080)"),
        ("username",    "Username (for auth testing)"),
        ("password",    "Password (for auth testing)"),
    ]

    for key, label in fields:
        current = SESSION.get(key, "")
        disp = "***" if key == "password" and current else current
        hint = f"  {DIM}[{disp}]{RST}" if current else ""
        val = input(f"  {NEON_GRN}[?]{RST} {label:<40}{hint}: ").strip()
        if val:
            SESSION[key] = val

    success("Session configured!")
    _show_scope()
    _arm_session_monitor()
    save_session()


def _arm_session_monitor() -> None:
    """Learn what an authenticated response looks like, before any scanning.

    A long scan outlives its cookie. Without a baseline taken while the session
    is known good, the run simply continues unauthenticated and reports the
    application clean - a failure that looks exactly like a clean result.
    """
    if not (SESSION.get("cookies") or SESSION.get("auth_token")):
        return
    from utils.http import get_client
    from utils.liveness import get_monitor
    try:
        get_monitor().establish(get_client())
    except Exception as exc:            # never block a run on the health check
        warn(f"Could not baseline session liveness: {exc}")


def _show_scope() -> None:
    """Print the scope every request will be checked against.

    Showing it at setup time is the point: an operator who sees 'unrestricted'
    knows nothing is fencing the scan in.
    """
    from utils.scope import current_scope
    scope = current_scope(SESSION)
    if scope.unscoped:
        warn("Scope: unrestricted - set a target or scope before scanning")
    else:
        info(f"Scope: {scope.describe()}")


# ── Session manager ───────────────────────────────────────────────────────────
def session_manager():
    from utils.helpers import print_banner
    print_banner("SESSION MANAGER", "Manage your engagement session")
    print(f"""
  {NEON_CYN}[1]{RST} Show current session
  {NEON_CYN}[2]{RST} Save session to file
  {NEON_CYN}[3]{RST} Load session from file
  {NEON_CYN}[4]{RST} Edit session fields
  {NEON_CYN}[5]{RST} Clear session
  {NEON_GRN}[0]{RST} Back
""")
    c = input(f"  {NEON_GRN}[?]{RST} Choice: ").strip()

    if c == "1":
        safe = {k: ("***" if k in ("password", "auth_token") else v)
                for k, v in SESSION.items()
                if k not in ("commands_run",)}
        print(json.dumps(safe, indent=2, default=str))

    elif c == "2":
        save_session()
        success("Session saved!")

    elif c == "3":
        path = prompt("Session file path")
        if os.path.exists(path):
            from config.settings import load_session
            load_session(path)
            success("Session loaded!")
        else:
            error("File not found")

    elif c == "4":
        session_setup()

    elif c == "5":
        for k in ["target_url", "cookies", "auth_token", "username", "password",
                  "proxy", "engagement"]:
            SESSION[k] = ""
        SESSION["findings"] = []
        SESSION["vulns_found"] = []
        success("Session cleared")

    input(f"\n  {NEON_GRN}[Enter]{RST} to return...")


# ── Tool checker ──────────────────────────────────────────────────────────────
def tool_checker():
    from utils.helpers import print_banner
    print_banner("TOOL CHECKER", "Verify installed security testing tools")

    groups = {
        "Recon":       ["nmap", "subfinder", "amass", "assetfinder", "whatweb", "wafw00f"],
        "Bruteforce":  ["gobuster", "ffuf", "dirb", "feroxbuster", "dirsearch"],
        "Vuln Scan":   ["nikto", "sqlmap", "nuclei", "xsstrike", "dalfox"],
        "Auth":        ["hydra", "medusa", "hashcat", "john", "wpscan"],
        "CMS":         ["wpscan", "droopescan", "joomscan"],
        "TLS/SSL":     ["testssl", "sslscan"],
        "Misc":        ["curl", "jq", "python3", "go"],
        "AI":          ["anthropic"],
    }

    # Several tools ship under more than one executable name depending on how
    # they were installed (distro package vs. pip vs. upstream script), so a
    # single which() lookup reported false MISSING results.
    aliases = {
        "testssl":     ["testssl", "testssl.sh"],
        "dirsearch":   ["dirsearch", "dirsearch.py"],
        "xsstrike":    ["xsstrike", "XSStrike", "xsstrike.py"],
        "subfinder":   ["subfinder"],
        "droopescan":  ["droopescan"],
        "feroxbuster": ["feroxbuster"],
    }

    def _present(tool: str) -> bool:
        if tool == "anthropic":
            return _HAS_ANTHROPIC
        which = __import__("shutil").which
        return any(which(n) for n in aliases.get(tool, [tool]))

    rows = []
    total = found = 0
    for group, tools in groups.items():
        for tool in tools:
            present = _present(tool)
            total += 1
            if present:
                found += 1
            status = f"{NEON_GRN}{BOLD}● READY{RST}" if present else f"{NEON_RED}{BOLD}○ MISSING{RST}"
            rows.append([group, tool, status])

    print_table(["Group", "Tool", "Status"], rows,
                f"Tool availability - {NEON_GRN}{found}{RST}/{total} ready")

    print(f"""
  {NEON_CYN}Install missing tools:{RST}
    apt install nmap nikto sqlmap gobuster ffuf dirb hydra hashcat john wpscan \\
                feroxbuster wafw00f whatweb
    pip install anthropic dalfox xsstrike subfinder droopescan
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/hahwul/dalfox/v2@latest
""")
    input(f"\n  {NEON_GRN}[Enter]{RST} to return...")


try:
    import anthropic as _ant  # noqa: F401  - availability probe, not called directly
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False


# ── Dispatch ──────────────────────────────────────────────────────────────────
def normalize_choice(choice: str) -> str:
    """Menu keys are a mix of digits and letters (A/C/W/O). Users naturally type
    the letters in lower case, which used to fall straight through to "Invalid
    choice", so fold case before looking anything up."""
    return choice.strip().upper()


def dispatch(choice: str) -> bool:
    choice = normalize_choice(choice)
    if choice not in MODULES:
        warn(f"Invalid choice: {choice!r}")
        info(f"Valid options: {', '.join(valid_choices())}")
        return False
    name, mod_path = MODULES[choice]
    if mod_path is None:
        return True
    try:
        mod = importlib.import_module(mod_path)
        importlib.reload(mod)
        mod.run()
    except ImportError as e:
        error(f"Module load error: {e}")
    except NonInteractive:
        warn(f"[{name}] needs interactive input - no terminal available.")
        info("Run it from a terminal, or drive this module through the MCP server.")
    except KeyboardInterrupt:
        warn("Interrupted")
    except Exception as e:
        error(f"Error in [{name}]: {e}")
        import traceback
        print(traceback.format_exc())
    finally:
        # Always wait for Enter before clearing screen and showing main menu
        try:
            input(f"\n  {NEON_GRN}[↵]{RST} Press Enter to return to main menu...")
        except (EOFError, KeyboardInterrupt):
            pass
    return True


# ── Args ──────────────────────────────────────────────────────────────────────
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="YeepForge Web Application Pentest Framework"
    )
    parser.add_argument("--target", metavar="URL", help="Set target URL")
    parser.add_argument("--module", metavar="N",  help="Run module directly by number")
    parser.add_argument("--session", metavar="PATH", help="Load session file")
    parser.add_argument("--scope", metavar="PATTERNS",
                        help="In-scope hosts, comma separated. Wildcards allowed and "
                             "'!' excludes: '*.example.com,!admin.example.com'. "
                             "Defaults to the target host and its subdomains.")
    parser.add_argument("--proxy", metavar="URL",
                        help="Route every request through a proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--rps", metavar="N", type=float,
                        help="Request rate cap per second (default 10, 0 = unlimited)")
    parser.add_argument("--scope-audit", action="store_true",
                        help="Report out-of-scope requests instead of blocking them")
    parser.add_argument("--browser", dest="browser", action="store_true", default=None,
                        help="Render pages in headless Chromium while crawling "
                             "(needed to see the surface of a JavaScript application)")
    parser.add_argument("--no-browser", dest="browser", action="store_false",
                        help="Never launch a browser; parse served HTML only")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--list-modules", action="store_true",
                        help="Print every menu key with its module path and exit")
    parser.add_argument("--non-interactive", action="store_true",
                        help="Never block on a prompt; unanswered prompts take their "
                             "default (submenus return, gates decline). Use with --module.")
    return parser.parse_args(argv)


def list_modules() -> None:
    rows = []
    for key in valid_choices():
        name, mod_path = MODULES[key]
        rows.append([key, name, mod_path or "built-in"])
    print_table(["Key", "Module", "Import path"], rows,
                f"{len(rows)} dispatchable commands")


# ── Main ──────────────────────────────────────────────────────────────────────
def main(argv=None):
    global SHOW_BANNER
    args = parse_args(argv)

    if args.no_banner:
        SHOW_BANNER = False
    if args.list_modules:
        list_modules()
        sys.exit(0)
    if args.non_interactive:
        os.environ["YEEPFORGE_NONINTERACTIVE"] = "1"
    if args.session:
        load_session(args.session)
    if args.target:
        SESSION["target_url"] = args.target
    if args.scope:
        SESSION["scope"] = args.scope
    if args.proxy:
        SESSION["proxy"] = args.proxy
    # These reach the HTTP engine through the environment so that every code
    # path - CLI, MCP server, agent - reads the same configuration.
    if args.rps is not None:
        os.environ["YEEPFORGE_RPS"] = str(args.rps)
    if args.scope_audit:
        os.environ["YEEPFORGE_SCOPE"] = "audit"
    if args.browser is not None:
        os.environ["YEEPFORGE_BROWSER"] = "1" if args.browser else "0"

    try:
        session_setup()

        if args.module:
            choice = normalize_choice(args.module)
            if choice == "0":
                save_session()
                sys.exit(0)
            elif choice == "35":
                session_manager()
            elif choice == "36":
                tool_checker()
            else:
                dispatch(choice)
            sys.exit(0)

        while True:
            print_menu()
            try:
                choice = input(
                    f"\n  {NEON_GRN}┌─[{RST}{NEON_CYN}{BOLD}YeepForge{RST}{NEON_GRN}]─[{RST}"
                    f"{NEON_GRN}v{VERSION}{NEON_GRN}]{RST}\n"
                    f"  {NEON_GRN}└──▶{RST} "
                ).strip()
            except EOFError:
                # stdin ran dry. Reattach to the terminal if there is one;
                # otherwise there is nobody left to answer, so save and leave
                # instead of redrawing the menu forever.
                try:
                    sys.stdin = open("/dev/tty")
                    choice = input(f"\n  {NEON_GRN}└──▶{RST} ").strip()
                except Exception:
                    print()
                    info("No interactive terminal - exiting. "
                         "Use --module <key> to run a module directly.")
                    save_session()
                    sys.exit(0)

            choice = normalize_choice(choice)

            if choice == "0":
                save_session()
                findings = len(SESSION.get("findings", [])) + len(SESSION.get("vulns_found", []))
                print()
                print(f"  {NEON_CYN}  Total findings  : {PURE_WHITE}{BOLD}{findings}{RST}")
                print(f"\n  {NEON_GRN}{'─'*40}{RST}")
                print(f"  {NEON_GRN}{BOLD}Session saved. Happy hunting!{RST}")
                print(f"  {NEON_GRN}{'─'*40}{RST}\n")
                sys.exit(0)
            elif choice == "35":
                session_manager()
            elif choice == "36":
                tool_checker()
            else:
                dispatch(choice)

    except KeyboardInterrupt:
        print(f"\n\n  {NEON_RED}{BOLD}[!] Ctrl-C - saving session…{RST}")
        save_session()
        sys.exit(0)


if __name__ == "__main__":
    main()
