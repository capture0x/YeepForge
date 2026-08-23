"""
modules/sast.py
tmrswrr - SAST (Static Application Security Testing)
LLM-driven source code analysis using 15 specialized SAST skills.
Each skill mirrors the methodology from sast-skills-main:
  Phase 1: Architecture analysis
  Phase 2: Parallel vulnerability detection (SQLi, XSS, SSRF, RCE, XXE, …)
  Phase 3: Final consolidated report
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

try:
    import anthropic
    _HAS_ANTHROPIC = True
except ImportError:
    _HAS_ANTHROPIC = False

from config.settings import SESSION, add_vuln, save_session
from utils.helpers import (
    BOLD,
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SLATE,
    SOFT_WHITE,
    add_finding,
    error,
    info,
    print_banner,
    prompt,
    section,
    success,
    warn,
)

# ── Skill registry ────────────────────────────────────────────────────────────
SKILLS_DIR = Path(__file__).parent / "sast_skills"

SKILL_META: dict[str, tuple[str, str, str]] = {
    # key:           (menu label,              owasp,     results file)
    "sast-analysis":      ("Architecture Analysis",  "-",       "architecture.md"),
    "sast-sqli":          ("SQL Injection",           "A03",     "sqli-results.md"),
    "sast-xss":           ("Cross-Site Scripting",    "A03",     "xss-results.md"),
    "sast-ssrf":          ("SSRF",                   "A10",     "ssrf-results.md"),
    "sast-rce":           ("Remote Code Execution",   "A03",     "rce-results.md"),
    "sast-xxe":           ("XXE",                    "A03",     "xxe-results.md"),
    "sast-fileupload":    ("File Upload Security",    "A04",     "fileupload-results.md"),
    "sast-pathtraversal": ("Path Traversal",          "A01",     "pathtraversal-results.md"),
    "sast-ssti":          ("SSTI",                   "A03",     "ssti-results.md"),
    "sast-jwt":           ("JWT Security",            "A07",     "jwt-results.md"),
    "sast-idor":          ("IDOR",                   "A01",     "idor-results.md"),
    "sast-missingauth":   ("Missing Auth",            "A07",     "missingauth-results.md"),
    "sast-businesslogic": ("Business Logic Flaws",    "A04",     "businesslogic-results.md"),
    "sast-graphql":       ("GraphQL Security",         "A03",     "graphql-results.md"),
    "sast-report":        ("Generate Final Report",   "-",       "final-report.md"),
}

MODEL      = "claude-opus-4-7"
MAX_TOKENS = 8192

# Max bytes of source code to send per API call
MAX_CODE_BYTES = 120_000

# File extensions to include in codebase reads
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go",
    ".java", ".cs", ".cpp", ".c", ".h", ".rs", ".swift",
    ".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs",
    ".erb", ".hbs", ".pug", ".jade", ".twig", ".blade.php",
    ".sql", ".graphql", ".gql",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".env.example",
    ".sh", ".bash", ".dockerfile",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".env", "dist", "build", "vendor", "bower_components",
    ".next", ".nuxt", "coverage", ".cache",
}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _skill_path(skill_key: str) -> Path:
    return SKILLS_DIR / skill_key / "SKILL.md"


def _load_skill(skill_key: str) -> str:
    p = _skill_path(skill_key)
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8")
    # Strip YAML frontmatter
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            text = text[end + 3:].lstrip("\n")
    return text


def _sast_dir(target_dir: str) -> Path:
    d = Path(target_dir) / "sast"
    d.mkdir(exist_ok=True)
    return d


def _read_codebase(target_dir: str, max_bytes: int = MAX_CODE_BYTES) -> str:
    """
    Walk target_dir, collect source files, return a formatted string
    with file paths and contents, truncated to max_bytes total.
    Security-sensitive files are prioritized.
    """
    root = Path(target_dir)
    if not root.is_dir():
        return ""

    priority_keywords = {
        "auth", "login", "jwt", "token", "session", "password", "user",
        "admin", "upload", "query", "sql", "db", "database", "model",
        "route", "view", "controller", "middleware", "api", "graphql",
        "template", "render", "exec", "command", "shell", "serialize",
        "deserialize", "xml", "parse", "request", "fetch", "http",
    }

    all_files: list[tuple[int, Path]] = []
    for path in root.rglob("*"):
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        # Handle .blade.php
        name_lower = path.name.lower()
        if suffix not in CODE_EXTENSIONS and not name_lower.endswith(".blade.php"):
            continue

        priority = sum(
            1 for kw in priority_keywords if kw in name_lower
        )
        all_files.append((-priority, path))  # negative for descending sort

    all_files.sort()

    collected: list[str] = []
    total = 0
    for _, fpath in all_files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(fpath.relative_to(root))
        entry = f"\n### FILE: {rel}\n```\n{content}\n```\n"
        entry_bytes = len(entry.encode())
        if total + entry_bytes > max_bytes:
            collected.append(f"\n### FILE: {rel}\n[... truncated - total limit reached ...]\n")
            break
        collected.append(entry)
        total += entry_bytes

    return "".join(collected)


OLLAMA_URL = "http://127.0.0.1:11434"


def _ollama_models_sast() -> list[str]:
    import urllib.request
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=4) as r:
            data = json.loads(r.read())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def _best_model_sast(models: list[str]) -> str:
    preferred = ["qwen", "llama3", "llama2", "mistral", "deepseek", "gemma", "phi"]
    for pref in preferred:
        for m in models:
            if pref in m.lower():
                return m
    return models[0] if models else "llama3.2"


def _check_ollama() -> tuple[bool, list[str]]:
    models = _ollama_models_sast()
    return bool(models), models


def _get_client() -> tuple[object | None, str]:
    """
    Returns (client_or_None, backend_label).
    Priority: Ollama (if running) → Claude (only if ANTHROPIC_API_KEY env var set).
    """
    # 1. Ollama first - free, local, no key needed
    models = _ollama_models_sast()
    if models:
        model = _best_model_sast(models)
        return None, f"Ollama ({model})"

    # 2. Claude - only if ANTHROPIC_API_KEY explicitly in environment
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if _HAS_ANTHROPIC and api_key:
        try:
            client = anthropic.Anthropic(api_key=api_key)
            return client, f"Claude {MODEL}"
        except Exception as e:
            warn(f"Claude API failed: {e}")

    return None, ""


def _call_claude(client, system: str, user_msg: str, label: str = "") -> str:
    info(f"Analyzing{f' ({label})' if label else ''}…")
    # Claude API
    if _HAS_ANTHROPIC and client:
        try:
            resp = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            return resp.content[0].text
        except Exception as e:
            error(f"Claude API error: {e}")
            warn("Falling back to Ollama…")

    # Ollama fallback - pick best available model
    import urllib.request as _ur
    models = _ollama_models_sast()
    model  = _best_model_sast(models) if models else "llama3.2"
    try:
        payload = json.dumps({
            "model": model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user_msg}],
            "stream": False,
        }).encode()
        req = _ur.Request(
            f"{OLLAMA_URL}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with _ur.urlopen(req, timeout=180) as r:
            data = json.loads(r.read())
            return data.get("message", {}).get("content", "")
    except Exception as e:
        return f"[No AI response - set ANTHROPIC_API_KEY or start Ollama: {e}]"


def _print_result_preview(text: str, lines: int = 40) -> None:
    """Pretty-print the first N lines of a SAST result."""
    print(f"\n{NEON_GRN}{'─'*68}{RST}")
    for line in text.splitlines()[:lines]:
        if line.startswith("#"):
            print(f"  {NEON_CYN}{BOLD}{line}{RST}")
        elif "[VULNERABLE]" in line or "VULNERABLE" in line.upper():
            print(f"  {NEON_RED}{BOLD}{line}{RST}")
        elif "[LIKELY" in line:
            print(f"  {NEON_YEL}{line}{RST}")
        elif "[NOT VULNERABLE]" in line:
            print(f"  {NEON_GRN}{line}{RST}")
        elif line.startswith("- **") or line.startswith("| "):
            print(f"  {NEON_CYN}{line}{RST}")
        else:
            print(f"  {PURE_WHITE}{line}{RST}")
    total_lines = len(text.splitlines())
    if total_lines > lines:
        print(f"  {DIM}… {total_lines - lines} more lines (see result file){RST}")
    print(f"{NEON_GRN}{'─'*68}{RST}\n")


def _extract_findings(result_text: str, skill_key: str) -> list[dict]:
    """Parse VULNERABLE/LIKELY VULNERABLE findings from result markdown."""
    findings = []
    import re
    owasp = SKILL_META.get(skill_key, ("", "", ""))[1]

    for m in re.finditer(r"###\s*\[VULNERABLE\]\s*(.+?)(?=\n###|\Z)", result_text, re.S):
        block = m.group(0)
        title_m = re.search(r"\[VULNERABLE\]\s*(.+)", block)
        title = title_m.group(1).strip() if title_m else "Finding"
        file_m = re.search(r"\*\*File\*\*:\s*`([^`]+)`", block)
        detail_m = re.search(r"\*\*Issue\*\*:\s*(.+)", block)
        findings.append({
            "title":    title,
            "severity": "High",
            "owasp":    owasp,
            "detail":   detail_m.group(1).strip() if detail_m else "",
            "url":      file_m.group(1) if file_m else "",
        })

    for m in re.finditer(r"###\s*\[LIKELY VULNERABLE\]\s*(.+?)(?=\n###|\Z)", result_text, re.S):
        block = m.group(0)
        title_m = re.search(r"\[LIKELY VULNERABLE\]\s*(.+)", block)
        title = title_m.group(1).strip() if title_m else "Finding"
        file_m = re.search(r"\*\*File\*\*:\s*`([^`]+)`", block)
        detail_m = re.search(r"\*\*Issue\*\*:\s*(.+)", block)
        findings.append({
            "title":    f"[Likely] {title}",
            "severity": "Medium",
            "owasp":    owasp,
            "detail":   detail_m.group(1).strip() if detail_m else "",
            "url":      file_m.group(1) if file_m else "",
        })

    return findings


# ── Core skill runner ─────────────────────────────────────────────────────────
def run_skill(skill_key: str, target_dir: str, client) -> str:
    """
    Run a single SAST skill against target_dir using Claude API.
    Returns the raw result text (also saved to sast/results file).
    """
    label, owasp, results_file = SKILL_META[skill_key]
    sast_d = _sast_dir(target_dir)
    out_path = sast_d / results_file

    # Skip if already done (resume-friendly)
    if out_path.exists() and prompt(f"{results_file} exists. Re-run? [y/N]").lower() != "y":
        info(f"Using existing: {out_path}")
        return out_path.read_text()

    skill_instruction = _load_skill(skill_key)
    if not skill_instruction:
        error(f"SKILL.md not found for {skill_key}")
        return ""

    # For report skill, read existing results files instead of codebase
    if skill_key == "sast-report":
        existing = []
        for sk, (_, _, rf) in SKILL_META.items():
            fp = sast_d / rf
            if fp.exists() and rf != "final-report.md":
                existing.append(f"\n## {rf}\n{fp.read_text()}\n")
        arch_f = sast_d / "architecture.md"
        arch = arch_f.read_text() if arch_f.exists() else "(architecture.md not found)"
        codebase_ctx = f"## sast/architecture.md\n{arch}\n\n" + "".join(existing)
    else:
        # Read architecture.md for context (except for analysis skill itself)
        arch_f = sast_d / "architecture.md"
        arch_ctx = ""
        if arch_f.exists() and skill_key != "sast-analysis":
            arch_ctx = f"\n## sast/architecture.md (architecture context)\n{arch_f.read_text()}\n\n"

        info(f"Reading codebase: {target_dir} …")
        codebase = _read_codebase(target_dir)
        codebase_ctx = arch_ctx + f"## Codebase Files\n{codebase}"

    system_prompt = (
        f"You are an expert security engineer performing a SAST (Static Application Security Testing) "
        f"assessment. Follow the methodology below precisely.\n\n"
        f"SKILL INSTRUCTIONS:\n{skill_instruction}\n\n"
        f"IMPORTANT RULES:\n"
        f"- Be thorough and precise. False negatives are worse than false positives.\n"
        f"- Output ONLY the findings document (Markdown). No preamble.\n"
        f"- Use the exact output format specified in the skill instructions.\n"
        f"- Do not skip Phase 1/2/3 methodology - adapt it to single-session analysis.\n"
    )

    user_msg = (
        f"Analyze this codebase for the {label} vulnerability category.\n"
        f"Save your results in the exact format specified.\n\n"
        f"{codebase_ctx}"
    )

    result = _call_claude(client, system_prompt, user_msg, label=label)

    # Save results
    out_path.write_text(result, encoding="utf-8")
    success(f"Results saved → {out_path}")

    # Extract findings into session
    findings = _extract_findings(result, skill_key)
    for f in findings:
        add_vuln(f["title"], f["severity"], f["owasp"], f["detail"], f["url"])
        add_finding(SESSION, f["title"], f["severity"], f["detail"], f["owasp"])

    if findings:
        success(f"Extracted {len(findings)} finding(s) into session")

    return result


# ── Full scan ─────────────────────────────────────────────────────────────────
def full_sast_scan(target_dir: str, client) -> None:
    """Run all SAST skills in sequence (analysis first, then all checks, then report)."""
    warn("Full SAST scan - this will analyze the entire codebase with all 15 skills")
    warn("Estimated time: 5-15 minutes depending on codebase size")
    if prompt("Confirm? [yes/no]").lower() != "yes":
        info("Aborted")
        return

    order = [
        "sast-analysis",
        "sast-sqli", "sast-xss", "sast-ssrf", "sast-rce", "sast-xxe",
        "sast-fileupload", "sast-pathtraversal", "sast-ssti",
        "sast-jwt", "sast-idor", "sast-missingauth",
        "sast-businesslogic", "sast-graphql",
        "sast-report",
    ]

    sast_d = _sast_dir(target_dir)
    total = len(order)

    for i, skill_key in enumerate(order, 1):
        label = SKILL_META[skill_key][0]
        section(f"[{i}/{total}] {label}")

        results_file = SKILL_META[skill_key][2]
        out_path = sast_d / results_file
        if out_path.exists():
            info(f"Already done ({results_file}) - skipping")
            continue

        result = run_skill(skill_key, target_dir, client)
        if result:
            _print_result_preview(result, lines=20)
        time.sleep(1)

    success("\nFull SAST scan complete!")
    final = sast_d / "final-report.md"
    if final.exists():
        info(f"Final report: {final}")


# ── Menu helpers ──────────────────────────────────────────────────────────────
def _show_sast_status(target_dir: str) -> None:
    """Show which scans have been completed."""
    sast_d = Path(target_dir) / "sast"
    print(f"\n  {NEON_CYN}SAST status for:{RST}  {PURE_WHITE}{target_dir}{RST}")
    print(f"  {NEON_GRN}{'─'*60}{RST}")
    for skill_key, (label, owasp, rf) in SKILL_META.items():
        done = (sast_d / rf).exists() if sast_d.is_dir() else False
        status = f"{NEON_GRN}✓ Done  {RST}" if done else f"{SLATE}○ Pending{RST}"
        owasp_s = f"{NEON_CYN}{owasp}{RST}" if owasp != "-" else f"{DIM}-{RST}"
        print(f"  {status}  {owasp_s}  {PURE_WHITE}{label}{RST}")
    print()


def _open_result(target_dir: str, skill_key: str) -> None:
    """Display a saved result file."""
    results_file = SKILL_META[skill_key][2]
    fp = Path(target_dir) / "sast" / results_file
    if not fp.exists():
        warn(f"Not yet run - {fp}")
        return
    _print_result_preview(fp.read_text(), lines=60)
    if prompt("Open full file in less? [y/N]").lower() == "y":
        os.system(f"less '{fp}'")


# ── Main run function ─────────────────────────────────────────────────────────
def run() -> None:
    print_banner(
        "SAST - STATIC APPLICATION SECURITY TESTING",
        "Claude AI · 15 specialized skills · Architecture analysis + full vulnerability detection"
    )

    # Target codebase setup
    target_dir = SESSION.get("sast_target", "")
    if not target_dir or not os.path.isdir(target_dir):
        target_dir = prompt("Path to target codebase directory")
        if not target_dir or not os.path.isdir(target_dir):
            error("Invalid directory")
            return
        SESSION["sast_target"] = target_dir
        save_session()

    # AI backend
    client, backend_label = _get_client()
    if backend_label:
        success(f"AI Backend: {NEON_CYN}{backend_label}{RST}")
    else:
        warn("No AI backend - set ANTHROPIC_API_KEY or start Ollama (ollama serve)")
        if not _HAS_ANTHROPIC:
            warn("anthropic library missing: pip install anthropic")
        api_key = prompt("Enter Anthropic API key (Enter to continue without AI)")
        if api_key and _HAS_ANTHROPIC:
            try:
                client = anthropic.Anthropic(api_key=api_key)
                SESSION["_api_key"] = api_key
                backend_label = f"Claude {MODEL}"
                success(f"Claude API connected ({MODEL})")
            except Exception as e:
                error(f"Invalid key: {e}")

    while True:
        _show_sast_status(target_dir)
        print(f"""
  {NEON_GRN}Codebase:{RST}  {PURE_WHITE}{target_dir}{RST}

  {NEON_CYN}{BOLD}── PHASE 0 - SETUP ─────────────────────────────────{RST}
    {NEON_CYN}[S]{RST}  Change target codebase directory
    {NEON_CYN}[V]{RST}  View / open a result file
    {NEON_CYN}[F]{RST}  Full SAST scan (all 15 skills)

  {NEON_CYN}{BOLD}── PHASE 1 - ARCHITECTURE ──────────────────────────{RST}
    {NEON_CYN}[ 1]{RST}  Architecture Analysis      {SOFT_WHITE}(run this first){RST}

  {NEON_CYN}{BOLD}── PHASE 2 - VULNERABILITY DETECTION ──────────────{RST}
    {NEON_CYN}[ 2]{RST}  SQL Injection              {SOFT_WHITE}A03 · sast-sqli{RST}
    {NEON_CYN}[ 3]{RST}  Cross-Site Scripting       {SOFT_WHITE}A03 · sast-xss{RST}
    {NEON_CYN}[ 4]{RST}  SSRF                       {SOFT_WHITE}A10 · sast-ssrf{RST}
    {NEON_CYN}[ 5]{RST}  Remote Code Execution      {SOFT_WHITE}A03 · sast-rce{RST}
    {NEON_CYN}[ 6]{RST}  XXE                        {SOFT_WHITE}A03 · sast-xxe{RST}
    {NEON_CYN}[ 7]{RST}  File Upload Security       {SOFT_WHITE}A04 · sast-fileupload{RST}
    {NEON_CYN}[ 8]{RST}  Path Traversal             {SOFT_WHITE}A01 · sast-pathtraversal{RST}
    {NEON_CYN}[ 9]{RST}  SSTI                       {SOFT_WHITE}A03 · sast-ssti{RST}
    {NEON_CYN}[10]{RST}  JWT Security               {SOFT_WHITE}A07 · sast-jwt{RST}
    {NEON_CYN}[11]{RST}  IDOR                       {SOFT_WHITE}A01 · sast-idor{RST}
    {NEON_CYN}[12]{RST}  Missing Auth               {SOFT_WHITE}A07 · sast-missingauth{RST}
    {NEON_CYN}[13]{RST}  Business Logic Flaws       {SOFT_WHITE}A04 · sast-businesslogic{RST}
    {NEON_CYN}[14]{RST}  GraphQL Security           {SOFT_WHITE}A03 · sast-graphql{RST}

  {NEON_CYN}{BOLD}── PHASE 3 - REPORT ────────────────────────────────{RST}
    {NEON_CYN}[15]{RST}  Generate Final Report      {SOFT_WHITE}sast-report{RST}

  {NEON_GRN}[ 0]{RST}  Back to main menu
""")

        choice_map = {
            "1":  "sast-analysis",
            "2":  "sast-sqli",
            "3":  "sast-xss",
            "4":  "sast-ssrf",
            "5":  "sast-rce",
            "6":  "sast-xxe",
            "7":  "sast-fileupload",
            "8":  "sast-pathtraversal",
            "9":  "sast-ssti",
            "10": "sast-jwt",
            "11": "sast-idor",
            "12": "sast-missingauth",
            "13": "sast-businesslogic",
            "14": "sast-graphql",
            "15": "sast-report",
        }

        c = prompt("Choice").strip().lower()

        if c == "0":
            break

        elif c == "s":
            new_dir = prompt("New codebase directory path")
            if os.path.isdir(new_dir):
                target_dir = new_dir
                SESSION["sast_target"] = target_dir
                save_session()
                success(f"Target set: {target_dir}")
            else:
                error("Directory not found")

        elif c == "v":
            print(f"\n  {NEON_CYN}Available result files:{RST}")
            choices = []
            for sk, (lbl, owasp, rf) in SKILL_META.items():
                fp = Path(target_dir) / "sast" / rf
                if fp.exists():
                    choices.append((sk, lbl, rf))
                    print(f"    {NEON_GRN}[{len(choices)}]{RST}  {lbl}  {DIM}({rf}){RST}")
            if not choices:
                warn("No results yet - run skills first")
            else:
                n = prompt("Select number")
                try:
                    idx = int(n) - 1
                    if 0 <= idx < len(choices):
                        _open_result(target_dir, choices[idx][0])
                except ValueError:
                    pass

        elif c == "f":
            full_sast_scan(target_dir, client)

        elif c in choice_map:
            skill_key = choice_map[c]
            label = SKILL_META[skill_key][0]

            # Warn if analysis not done yet (except for analysis itself)
            if skill_key != "sast-analysis":
                arch_f = Path(target_dir) / "sast" / "architecture.md"
                if not arch_f.exists():
                    warn("sast/architecture.md not found - run Architecture Analysis [1] first for best results")
                    if prompt("Continue anyway? [y/N]").lower() != "y":
                        continue

            section(f"Running: {label}")
            result = run_skill(skill_key, target_dir, client)
            if result:
                _print_result_preview(result)

        else:
            warn("Invalid choice")

        save_session()
