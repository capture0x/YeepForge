"""
modules/reporting.py
tmrswrr - Professional Report Generation (HTML, Markdown, JSON)
AdStrike-style: dark gradient header, finding cards, CVSS v3.1, OWASP coverage
"""
import datetime
import html as _html
import json

from config.settings import REPORTS_DIR, SESSION
from utils.helpers import (
    BOLD,
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    NEON_YEL,
    RST,
    SOFT_WHITE,
    info,
    print_banner,
    prompt,
    success,
)

VERSION = "1.0"


# ── Severity helpers ──────────────────────────────────────────────────────────
def _sev_score(sev: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}.get(sev, 0)


SEV_COLORS = {
    "Critical": "#e74c3c",
    "High":     "#e67e22",
    "Medium":   "#f39c12",
    "Low":      "#27ae60",
    "Info":     "#3498db",
}
SEV_BG = {
    "Critical": "#fdf2f2",
    "High":     "#fef9f2",
    "Medium":   "#fefdf2",
    "Low":      "#f2fdf4",
    "Info":     "#f2f8fd",
}


# ── CVSS v3.1 map ─────────────────────────────────────────────────────────────
CVSS_MAP = {
    "SQL Injection":                 ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Blind SQL Injection":           ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Remote Code Execution":         ("10.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "Command Injection":             ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "File Upload RCE":               ("10.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "Server-Side Request Forgery":   ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L"),
    "SSRF":                          ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L"),
    "Server-Side Template Injection":("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "SSTI":                          ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "HTTP Request Smuggling":        ("9.0",  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "XML External Entity":           ("8.6",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "XXE":                           ("8.6",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    "Stored XSS":                    ("8.8",  "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    "Reflected XSS":                 ("6.1",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Cross-Site Scripting":          ("6.1",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "CORS Misconfiguration":         ("8.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "CSRF":                          ("8.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    "Subdomain Takeover":            ("8.1",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "Path Traversal":                ("7.5",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Directory Traversal":           ("7.5",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "IDOR":                          ("6.5",  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "Insecure Direct Object":        ("6.5",  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "Open Redirect":                 ("6.1",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "Default Credentials":           ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "JWT":                           ("8.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "Missing HSTS":                  ("5.3",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Missing CSP":                   ("5.3",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Missing X-Frame-Options":       ("4.7",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "Clickjacking":                  ("4.7",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "Sensitive File Exposed":        ("7.5",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "GraphQL Introspection":         ("5.3",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "SQL Injection via GraphQL":     ("9.8",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "Cache Poisoning":               ("7.4",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N"),
    "CRLF Injection":                ("6.5",  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
}

OWASP_TAGS = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Auth Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


#: Fallback when a title matches no CVSS_MAP key. A report where only some rows
#: carry a score reads as though the others were never assessed, so every
#: finding gets one - derived from its severity, with a generic vector.
_SEV_CVSS = {
    "Critical": ("9.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "High":     ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "Medium":   ("5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "Low":      ("3.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
}


def _get_cvss(title: str, severity: str = "") -> tuple[str, str]:
    t = title.lower()
    for key, (score, vector) in CVSS_MAP.items():
        if key.lower() in t:
            return score, vector
    return _SEV_CVSS.get(severity, ("", ""))


def _merge(prev: dict, new: dict) -> dict:
    """Combine two reports of one issue, keeping whichever fields carry data.

    Neither copy is authoritative: one may hold the evidence, the other the URL
    or the remediation. Taking the union means a bare duplicate can never drop
    proof that the first copy already carried.
    """
    out = dict(prev)
    for k, v in new.items():
        if v and not out.get(k):
            out[k] = v
    return out


def _sorted_findings() -> list:
    """Every finding, deduplicated across both stores, worst severity first.

    The same issue routinely arrives twice - once in `findings`, once in
    `vulns_found` - and the two copies need not agree on the URL, since some
    callers omit it. Keying on (title, url) alone would let the bare copy
    survive as its own row, so titles are reconciled as a group first.
    """
    raw = SESSION.get("findings", []) + SESSION.get("vulns_found", [])

    by_title: dict[str, list] = {}
    for f in raw:
        by_title.setdefault(f.get("title", "").strip().lower(), []).append(f)

    deduped: list = []
    for group in by_title.values():
        located = [f for f in group if (f.get("url") or "").strip()]
        bare    = [f for f in group if not (f.get("url") or "").strip()]

        if not located:
            merged = dict(bare[0])
            for f in bare[1:]:
                merged = _merge(merged, f)
            deduped.append(merged)
            continue

        by_url: dict[str, dict] = {}
        for f in located:
            u = f["url"].strip()
            by_url[u] = _merge(by_url[u], f) if u in by_url else dict(f)

        # A copy with no URL adds no location, only possibly richer fields. Fold
        # it into the one known location; when the title spans several it cannot
        # say which it meant, so drop it rather than invent a placeless row.
        if len(by_url) == 1:
            only = next(iter(by_url))
            for f in bare:
                by_url[only] = _merge(by_url[only], f)
        deduped.extend(by_url.values())

    return sorted(deduped,
                  key=lambda x: _sev_score(x.get("severity", "Info")), reverse=True)


def _session_caveat() -> str:
    """Plain-language warning when the run outlived its session.

    A report whose scanning happened unauthenticated must say so on its face.
    Its findings are thin and its silences mean nothing, and a reader cannot
    tell that from the severity counts.
    """
    if not SESSION.get("session_degraded"):
        return ""
    reason = SESSION.get("session_degraded_reason", "the session stopped authenticating")
    return ("The engagement's session expired part-way through this assessment "
            f"({reason}). Testing continued as an anonymous user, so the findings "
            "below cover only what is reachable without logging in, and the absence "
            "of a finding is not evidence that the application is sound. Re-run with "
            "fresh credentials before treating this report as complete.")


def _overall_risk(findings: list) -> tuple[str, str]:
    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["Critical", "High", "Medium", "Low"]}
    if counts["Critical"] > 0:
        # Find highest CVSS
        top = 9.0
        for f in findings:
            score, _ = _get_cvss(f.get("title", ""), f.get("severity", ""))
            if score:
                top = max(top, float(score))
        return f"{top:.1f}", "Critical"
    if counts["High"] > 0:
        return "7.5", "High"
    if counts["Medium"] > 0:
        return "5.0", "Medium"
    if counts["Low"] > 0:
        return "3.0", "Low"
    return "0.0", "Info"


# ── CSS (AdStrike-style, adapted for YeepForge) ───────────────────────────────
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
  background: #f0f2f5;
  color: #1a1a2e;
  font-size: 14px;
  line-height: 1.6;
}
a { color: #2980b9; text-decoration: none; }
a:hover { text-decoration: underline; }

.report-header {
  background: linear-gradient(135deg, #0a1628 0%, #0d2137 50%, #0a2e1a 100%);
  color: #fff;
  padding: 48px 56px 36px;
  border-bottom: 4px solid #00c853;
}
.report-header h1 { font-size: 2.2em; font-weight: 700; letter-spacing: -0.5px; }
.report-header .subtitle { color: #a0aec0; margin-top: 6px; font-size: 0.95em; }
.header-meta {
  display: flex; gap: 32px; flex-wrap: wrap;
  margin-top: 24px; color: #cbd5e0; font-size: 0.88em;
}
.header-meta span strong { color: #fff; }

.risk-badge {
  display: inline-flex; flex-direction: column; align-items: center;
  background: rgba(255,255,255,0.08);
  border: 1px solid rgba(255,255,255,0.18);
  border-radius: 12px; padding: 16px 28px;
  margin-left: auto;
}
.risk-badge .risk-score { font-size: 3em; font-weight: 800; line-height: 1; }
.risk-badge .risk-label { font-size: 0.8em; letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; }

.container { max-width: 1280px; margin: 0 auto; padding: 36px 40px; }
.section {
  background: #fff; border-radius: 10px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
  padding: 28px 32px; margin-bottom: 28px;
}
.section-title {
  font-size: 1.15em; font-weight: 700; color: #1a1a2e;
  border-bottom: 2px solid #00c853;
  padding-bottom: 10px; margin-bottom: 20px;
  display: flex; align-items: center; gap: 10px;
}
.section-title .icon { font-size: 1.1em; }

.stat-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(110px,1fr));
  gap: 14px; margin-bottom: 24px;
}
.stat-card {
  background: #f8f9fa; border-radius: 8px;
  padding: 18px 12px; text-align: center;
  border-top: 3px solid #ddd;
}
.stat-card .stat-num { font-size: 2.2em; font-weight: 800; line-height: 1; }
.stat-card .stat-lbl { font-size: 0.78em; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }

.sev-badge {
  display: inline-block; padding: 2px 10px; border-radius: 20px;
  font-size: 0.78em; font-weight: 700; text-transform: uppercase;
  letter-spacing: .5px; color: #fff;
}
.owasp-pill {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 0.75em; font-weight: 600;
  background: #eef2ff; color: #3730a3;
  border: 1px solid #c7d2fe; margin: 1px 2px;
  font-family: 'Courier New', monospace; cursor: default;
}
.owasp-pill:hover { background: #3730a3; color: #fff; }

.cvss-badge {
  display: inline-block; padding: 3px 10px; border-radius: 4px;
  font-size: 0.8em; font-weight: 700; border: 1px solid;
}

.finding-card {
  border: 1px solid #e5e7eb; border-radius: 8px;
  margin-bottom: 18px; overflow: hidden;
}
.finding-header {
  display: flex; align-items: center; gap: 12px;
  padding: 14px 20px; border-bottom: 1px solid #e5e7eb;
}
.finding-id { font-size: .85em; font-weight: 700; color: #6b7280; min-width: 28px; }
.finding-name { font-weight: 700; font-size: 1.05em; flex: 1; }
.finding-body { padding: 18px 20px; background: #fafafa; }
.finding-body table { width: 100%; border-collapse: collapse; }
.finding-body td {
  padding: 8px 12px; vertical-align: top;
  border-bottom: 1px solid #f3f4f6;
}
.finding-body td:first-child {
  font-weight: 600; color: #4b5563; width: 150px; white-space: nowrap;
}
.finding-body tr:last-child td { border-bottom: none; }
.finding-body code {
  background: #f1f5f9; padding: 1px 5px; border-radius: 3px;
  font-family: 'Courier New', monospace; font-size: .9em; color: #1e293b;
}

.owasp-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px,1fr));
  gap: 12px;
}
.owasp-card {
  border-radius: 8px; padding: 14px 16px;
  border: 1px solid #e5e7eb; position: relative; overflow: hidden;
}
.owasp-card.covered { border-left: 4px solid #00c853; }
.owasp-card.notcovered { border-left: 4px solid #e5e7eb; opacity: .7; }
.owasp-card .owasp-id { font-weight: 800; font-size: .85em; color: #374151; }
.owasp-card .owasp-name { font-size: .82em; color: #6b7280; margin-top: 2px; }
.owasp-count { position: absolute; top: 8px; right: 10px;
  font-size: .7em; font-weight: 700; padding: 1px 7px;
  border-radius: 10px; color: #fff; }

.overview-table { width: 100%; border-collapse: collapse; }
.overview-table th {
  background: #0a1628; color: #fff;
  padding: 10px 14px; text-align: left; font-weight: 600; font-size: .88em;
}
.overview-table td {
  padding: 10px 14px; border-bottom: 1px solid #f3f4f6;
  vertical-align: top; font-size: .88em;
}
.overview-table tr:hover td { background: #f9fafb; }

.report-footer {
  text-align: center; padding: 28px; color: #9ca3af;
  font-size: .82em; border-top: 1px solid #e5e7eb; margin-top: 12px;
}

@media print {
  body { background: #fff; font-size: 12px; }
  .section { box-shadow: none; border: 1px solid #e5e7eb; page-break-inside: avoid; }
  .report-header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .finding-card { page-break-inside: avoid; }
}
"""


def _cvss_badge(score: str, vector: str = "") -> str:
    if not score:
        return ""
    s = float(score)
    if s >= 9.0:
        col, bg = "#e74c3c", "#fdf2f2"
    elif s >= 7.0:
        col, bg = "#e67e22", "#fef9f2"
    elif s >= 4.0:
        col, bg = "#f39c12", "#fefdf2"
    else:
        col, bg = "#27ae60", "#f2fdf4"
    tip = f' title="{_html.escape(vector)}"' if vector else ""
    return (f'<span class="cvss-badge"{tip} '
            f'style="color:{col};background:{bg};border-color:{col}">'
            f'CVSS {score}</span>')


_CONF_COLORS = {"Confirmed": "#00a86b", "Firm": "#f5a623", "Tentative": "#9ca3af"}


def _conf_badge(conf: str) -> str:
    """Confidence tells the reader which findings are proven vs. worth checking."""
    if not conf:
        return ""
    col = _CONF_COLORS.get(conf, "#9ca3af")
    return (f'<span class="sev-badge" style="background:transparent;color:{col};'
            f'border:1px solid {col}">{_html.escape(conf)}</span>')


def _evidence_html(finding: dict) -> str:
    """Render the raw request/response proving a finding, plus a repro command.

    This is what turns a scanner hit into something a client or a bounty triager
    can act on, so it is rendered verbatim (escaped) rather than summarised.
    """
    ev = finding.get("evidence")
    if not isinstance(ev, dict) or not ev:
        return ""

    def block(label: str, body: str) -> str:
        if not body:
            return ""
        return (f'<div style="margin-top:10px"><div style="font-size:.72em;font-weight:700;'
                f'letter-spacing:1px;text-transform:uppercase;color:#6b7280">{label}</div>'
                f'<pre style="background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;'
                f'overflow-x:auto;font-size:.78em;line-height:1.45;margin:4px 0 0">'
                f'{_html.escape(body)}</pre></div>')

    if "note" in ev and "url" not in ev:
        return f'<tr><td>Evidence</td><td>{block("Note", str(ev.get("note", "")))}</td></tr>'

    req = _EvidenceView(ev).request_text()
    res = _EvidenceView(ev).response_text()
    curl = ev.get("curl", "")
    ms = ev.get("elapsed_ms")
    timing = f'<div style="font-size:.76em;color:#6b7280;margin-top:6px">Round-trip: {ms} ms</div>' if ms else ""
    body = block("Request", req) + block("Response", res) + block("Reproduce", curl) + timing
    return f'<tr><td>Evidence</td><td>{body}</td></tr>' if body else ""


class _EvidenceView:
    """Render a stored evidence dict without importing the live HTTP layer.

    Reports are generated from session JSON that may have been written by an
    older run, so this reads defensively from plain keys instead of requiring a
    utils.http.Evidence instance.
    """

    def __init__(self, ev: dict):
        self.ev = ev

    def request_text(self) -> str:
        from urllib.parse import urlsplit
        url = self.ev.get("url", "")
        if not url:
            return ""
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.ev.get('method', 'GET')} {path} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in (self.ev.get("request_headers") or {}).items()]
        if self.ev.get("request_body"):
            lines += ["", str(self.ev["request_body"])]
        return "\n".join(lines)

    def response_text(self) -> str:
        status = self.ev.get("status")
        if status is None:
            err = self.ev.get("error")
            return f"(no response: {err})" if err else ""
        lines = [f"HTTP/1.1 {status}"]
        lines += [f"{k}: {v}" for k, v in (self.ev.get("response_headers") or {}).items()]
        if self.ev.get("response_body"):
            lines += ["", str(self.ev["response_body"])]
        return "\n".join(lines)


def _sev_badge(sev: str) -> str:
    col = SEV_COLORS.get(sev, "#7f8c8d")
    return f'<span class="sev-badge" style="background:{col}">{_html.escape(sev)}</span>'


def _owasp_pill(owasp: str) -> str:
    if not owasp:
        return ""
    code = owasp.split(":")[0] if ":" in owasp else owasp
    label = OWASP_TAGS.get(code, owasp)
    return f'<span class="owasp-pill" title="{_html.escape(label)}">{_html.escape(code)}:2021</span>'


def generate_html() -> str:
    findings  = _sorted_findings()
    ts        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target    = SESSION.get("target_url", "N/A")
    eng       = SESSION.get("engagement", "Web Application Pentest")
    tester    = SESSION.get("username", "").strip()
    tech      = ", ".join(SESSION.get("tech_stack", [])[:4]) or "N/A"

    risk_score, risk_level = _overall_risk(findings)
    risk_color = SEV_COLORS.get(risk_level, "#7f8c8d")

    caveat = _session_caveat()
    session_banner = (
        '<div style="margin:16px 0;padding:14px 18px;border-left:4px solid #dc2626;'
        'background:#fef2f2;border-radius:6px;line-height:1.7;color:#7f1d1d">'
        f'<strong>INCOMPLETE ASSESSMENT.</strong> {_html.escape(caveat)}</div>'
    ) if caveat else ""

    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}

    # ── Executive narrative ───────────────────────────────────────────────────
    crits = [f for f in findings if f.get("severity") == "Critical"]
    highs = [f for f in findings if f.get("severity") == "High"]
    sev_parts = []
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        n = counts[sev]
        if n:
            c = SEV_COLORS[sev]
            sev_parts.append(f"<span style='color:{c};font-weight:600'>{n} {sev}</span>")
    narrative = (
        f"An authorized web application security assessment was conducted against "
        f"<strong>{_html.escape(target)}</strong> as part of the "
        f"<strong>{_html.escape(eng)}</strong> engagement. "
    )
    if findings:
        narrative += (
            f"The assessment identified <strong>{len(findings)}</strong> security "
            f"finding(s): {', '.join(sev_parts)}. "
        )
        if crits:
            names = ", ".join(f"<em>{_html.escape(f.get('title','?')[:60])}</em>"
                              for f in crits[:2])
            narrative += (
                f"<strong style='color:{SEV_COLORS['Critical']}'>Critical</strong> "
                f"findings include {names}, representing immediate risk of "
                f"application compromise. "
            )
        narrative += (
            f"The overall risk rating is "
            f"<strong style='color:{risk_color}'>{risk_level} (CVSS {risk_score})</strong>. "
            f"Immediate remediation is required for all Critical and High findings."
        )
    else:
        narrative += "No security findings were identified during this assessment."

    # ── Stat grid ─────────────────────────────────────────────────────────────
    stat_cards = ""
    for sev, lbl in [("Critical","Critical"),("High","High"),("Medium","Medium"),
                     ("Low","Low"),("Info","Info")]:
        n   = counts[sev]
        col = SEV_COLORS[sev]
        stat_cards += (
            f'<div class="stat-card" style="border-top-color:{col}">'
            f'<div class="stat-num" style="color:{col}">{n}</div>'
            f'<div class="stat-lbl">{lbl}</div></div>'
        )
    stat_cards += (
        f'<div class="stat-card" style="border-top-color:#0a1628">'
        f'<div class="stat-num" style="color:#0a1628">{len(findings)}</div>'
        f'<div class="stat-lbl">Total</div></div>'
    )
    endpoints = len(SESSION.get("endpoints", []))
    if endpoints:
        stat_cards += (
            f'<div class="stat-card" style="border-top-color:#00c853">'
            f'<div class="stat-num" style="color:#00c853">{endpoints}</div>'
            f'<div class="stat-lbl">Endpoints</div></div>'
        )

    # ── Findings index table ──────────────────────────────────────────────────
    index_rows = ""
    for i, f in enumerate(findings, 1):
        sev   = f.get("severity", "Info")
        owasp = f.get("owasp", "")
        score, vec = _get_cvss(f.get("title", ""), f.get("severity", ""))
        url_short  = (f.get("url", "") or "")[:60]
        index_rows += f"""
        <tr>
          <td style="font-weight:700;color:#6b7280">{i:02d}</td>
          <td>{_sev_badge(sev)}</td>
          <td>{_cvss_badge(score)}</td>
          <td style="font-weight:600">{_html.escape(f.get('title','')[:70])}</td>
          <td>{_owasp_pill(owasp)}</td>
          <td style="font-family:'Courier New',monospace;font-size:.82em;color:#6b7280"
              title="{_html.escape(f.get('url',''))}">
              {_html.escape(url_short)}</td>
        </tr>"""

    # ── Finding cards ─────────────────────────────────────────────────────────
    finding_cards = ""
    for i, f in enumerate(findings, 1):
        sev     = f.get("severity", "Info")
        col     = SEV_COLORS.get(sev, "#7f8c8d")
        bg      = SEV_BG.get(sev, "#f9fafb")
        owasp   = f.get("owasp", "")
        score, vec = _get_cvss(f.get("title", ""), f.get("severity", ""))
        detail  = _html.escape(f.get("detail", "") or "")
        url     = _html.escape(f.get("url", "") or "")
        ts_f    = f.get("time", "")[:16]

        owasp_code = owasp.split(":")[0] if ":" in owasp else owasp
        owasp_name = OWASP_TAGS.get(owasp_code, owasp)

        # Remediation hint
        remediations = {
            "SQL Injection":   "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            "XSS":             "Encode all output with context-aware encoding. Implement a strict Content-Security-Policy.",
            "SSRF":            "Whitelist allowed protocols/hosts. Block internal address ranges at the network layer.",
            "Path Traversal":  "Validate file paths against an allowlist. Use chroot jails or containerization.",
            "CORS":            "Set Access-Control-Allow-Origin to specific trusted origins only. Never use wildcard with credentials.",
            "Default Credentials": "Change all default passwords immediately. Enforce strong password policy.",
            "Missing HSTS":    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
            "Missing CSP":     "Implement a Content-Security-Policy header restricting script sources.",
            "Clickjacking":    "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors: none'.",
            "IDOR":            "Implement server-side authorization checks on every object access.",
            "Open Redirect":   "Validate redirect URLs against an allowlist. Reject absolute URLs.",
            "SSTI":            "Never render user input in template strings. Use sandboxed template engines.",
        }
        # A remediation written for this specific finding beats the generic
        # hint - the reporter must never discard what the tester supplied.
        rem = (f.get("remediation") or "").strip()
        if not rem:
            for key, hint in remediations.items():
                if key.lower() in f.get("title", "").lower():
                    rem = hint
                    break

        finding_cards += f"""
<div class="finding-card">
  <div class="finding-header" style="background:{bg}">
    <div class="finding-id">#{i:02d}</div>
    {_sev_badge(sev)}
    <div class="finding-name">{_html.escape(f.get('title',''))}</div>
    {_cvss_badge(score, vec)}
    {_owasp_pill(owasp)}
    {_conf_badge(f.get('confidence', ''))}
  </div>
  <div class="finding-body">
    <table>
      <tr><td>Category</td><td>{_html.escape(owasp_name or owasp)}</td></tr>
      {'<tr><td>Description</td><td>' + detail + '</td></tr>' if detail else ''}
      {'<tr><td>Affected URL</td><td><code>' + url + '</code></td></tr>' if url else ''}
      {'<tr><td>CWE</td><td>' + _html.escape(f.get('cwe', '')) + '</td></tr>' if f.get('cwe') else ''}
      {'<tr><td>Remediation</td><td>' + _html.escape(rem) + '</td></tr>' if rem else ''}
      {'<tr><td>CVSS Vector</td><td><code style="font-size:.78em">' + _html.escape(vec) + '</code></td></tr>' if vec else ''}
      {_evidence_html(f)}
      <tr><td>Discovered</td><td>{ts_f}</td></tr>
    </table>
  </div>
</div>"""

    # ── OWASP Top 10 coverage ─────────────────────────────────────────────────
    owasp_in_findings = set()
    for f in findings:
        o = f.get("owasp", "")
        code = o.split(":")[0] if ":" in o else o
        if code in OWASP_TAGS:
            owasp_in_findings.add(code)

    owasp_grid = ""
    for code, name in OWASP_TAGS.items():
        n_findings = sum(1 for f in findings
                         if code in f.get("owasp", ""))
        covered = code in owasp_in_findings
        cls     = "covered" if covered else "notcovered"
        col     = "#00c853" if covered else "#9ca3af"
        badge   = f'<span class="owasp-count" style="background:{col}">{n_findings if covered else "-"}</span>'
        owasp_grid += f"""
<div class="owasp-card {cls}" style="{'border-left-color:'+col if covered else ''}">
  {badge}
  <div class="owasp-id">{code}:2021</div>
  <div class="owasp-name">{name}</div>
</div>"""

    # ── Assemble HTML ─────────────────────────────────────────────────────────
    # Tester/author identity comes from the engagement (SESSION username) - never
    # a baked-in name. When unset, the report simply omits it.
    subtitle = (f"Web Application Security Assessment by {_html.escape(tester)}"
                if tester else "Web Application Security Assessment")
    tester_html = (f'\n        <span><strong>Tester:</strong> {_html.escape(tester)}</span>'
                   if tester else "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>YeepForge Report - {_html.escape(eng)}</title>
<style>{_CSS}</style>
</head>
<body>

<!-- Header -->
<div class="report-header">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:20px">
    <div>
      <div style="color:#00c853;font-size:.78em;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">
        WEB APPLICATION PENETRATION TEST REPORT - CONFIDENTIAL
      </div>
      <h1>{_html.escape(eng)}</h1>
      <div class="subtitle">{subtitle}</div>
      <div class="header-meta">
        <span><strong>Date:</strong> {ts}</span>{tester_html}
        <span><strong>Target:</strong> {_html.escape(target)}</span>
        <span><strong>Tech:</strong> {_html.escape(tech)}</span>
        <span><strong>Generated by:</strong> YeepForge v{VERSION}</span>
      </div>
    </div>
    <div class="risk-badge">
      <div class="risk-score" style="color:{risk_color}">{risk_score}</div>
      <div class="risk-label" style="color:{risk_color}">{risk_level} Risk</div>
      <div style="font-size:.72em;color:#718096;margin-top:2px">Overall CVSS</div>
    </div>
  </div>
</div>

<div class="container">

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title"><span class="icon">📋</span>Executive Summary</div>
    <div class="stat-grid">{stat_cards}</div>
    {session_banner}
    <p style="line-height:1.8;color:#374151">{narrative}</p>
  </div>

  <!-- Findings Index -->
  <div class="section">
    <div class="section-title"><span class="icon">🎯</span>Findings Overview</div>
    <table class="overview-table">
      <thead>
        <tr>
          <th>#</th><th>Severity</th><th>CVSS</th><th>Title</th>
          <th>OWASP</th><th>Affected URL</th>
        </tr>
      </thead>
      <tbody>{index_rows}</tbody>
    </table>
  </div>

  <!-- Detailed Findings -->
  <div class="section">
    <div class="section-title"><span class="icon">🔍</span>Detailed Findings</div>
    {finding_cards if finding_cards else '<p style="color:#6b7280">No findings recorded.</p>'}
  </div>

  <!-- OWASP Coverage -->
  <div class="section">
    <div class="section-title"><span class="icon">🛡️</span>OWASP Top 10 Coverage</div>
    <p style="color:#6b7280;font-size:.88em;margin-bottom:16px">
      OWASP Top 10 2021 categories tested in this engagement.
    </p>
    <div class="owasp-grid">{owasp_grid}</div>
  </div>

  <!-- Remediation -->
  <div class="section">
    <div class="section-title"><span class="icon">🔧</span>Remediation Priority</div>
    <table class="overview-table">
      <thead><tr><th>Priority</th><th>Severity</th><th>Timeframe</th><th>Action</th></tr></thead>
      <tbody>
        <tr><td style="font-weight:700">P1</td><td>{_sev_badge("Critical")}</td><td>24-48 hours</td>
            <td>Emergency patch or mitigate all Critical findings immediately</td></tr>
        <tr><td style="font-weight:700">P2</td><td>{_sev_badge("High")}</td><td>7 days</td>
            <td>Remediate all High findings in the current sprint</td></tr>
        <tr><td style="font-weight:700">P3</td><td>{_sev_badge("Medium")}</td><td>30 days</td>
            <td>Address Medium findings in the next release cycle</td></tr>
        <tr><td style="font-weight:700">P4</td><td>{_sev_badge("Low")}</td><td>Quarterly</td>
            <td>Schedule Low findings for the next quarterly security review</td></tr>
      </tbody>
    </table>
  </div>

</div>

<div class="report-footer">
  <strong>CONFIDENTIAL</strong> - Generated by YeepForge v{VERSION} on {ts} -
  Authorized penetration testing only - Not for distribution
</div>

</body>
</html>"""


def generate_markdown() -> str:
    findings = _sorted_findings()
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    target   = SESSION.get("target_url", "N/A")
    eng      = SESSION.get("engagement", "Web Pentest")
    tester   = SESSION.get("username", "").strip()
    risk_score, risk_level = _overall_risk(findings)

    counts = {s: sum(1 for f in findings if f.get("severity") == s)
              for s in ["Critical", "High", "Medium", "Low", "Info"]}

    lines = [
        "# Web Application Penetration Test Report",
        "",
        f"**Engagement:** {eng}  ",
        f"**Target:** {target}  ",
        *([f"**Tester:** {tester}  "] if tester else []),
        f"**Date:** {ts}  ",
        f"**Overall Risk:** {risk_level} (CVSS {risk_score})  ",
        f"**Tool:** YeepForge v{VERSION}  ",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        *([f"> **INCOMPLETE ASSESSMENT.** {_session_caveat()}", ""]
          if _session_caveat() else []),
        "| Severity | Count |",
        "|----------|-------|",
        *[f"| {s} | {counts.get(s, 0)} |"
          for s in ["Critical", "High", "Medium", "Low", "Info"]],
        f"| **Total** | **{len(findings)}** |",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    for i, f in enumerate(findings, 1):
        score, vec = _get_cvss(f.get("title", ""), f.get("severity", ""))
        lines += [
            f"### {i:02d}. [{f.get('severity','Info')}] {f.get('title','?')}",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Severity | **{f.get('severity','Info')}** |",
            f"| CVSS | {score} |",
            f"| OWASP | {f.get('owasp','')} |",
            f"| URL | `{f.get('url','')}` |",
            f"| Detail | {f.get('detail','')} |",
            f"| Confidence | {f.get('confidence','')} |",
            f"| Discovered | {f.get('time','')[:16]} |",
            "",
        ]
        lines += _evidence_markdown(f)

    lines += [
        "---",
        "",
        "## OWASP Top 10 Coverage",
        "",
        "| Category | Description | Status |",
        "|----------|-------------|--------|",
        *[f"| {k}:2021 | {v} | {'✅ Tested' if any(k in f.get('owasp','') for f in findings) else '⬜ Not tested'} |"
          for k, v in OWASP_TAGS.items()],
        "",
        "---",
        "",
        f"*CONFIDENTIAL - Generated by YeepForge v{VERSION} - Authorized testing only*",
    ]

    return "\n".join(lines)


def _evidence_markdown(finding: dict) -> list[str]:
    """Evidence as fenced blocks - the shape bounty platforms accept verbatim."""
    ev = finding.get("evidence")
    if not isinstance(ev, dict) or not ev:
        return []
    if "note" in ev and "url" not in ev:
        return ["**Evidence**", "", "```", str(ev.get("note", "")), "```", ""]

    view = _EvidenceView(ev)
    out: list[str] = []
    for label, body, lang in (
        ("Request", view.request_text(), "http"),
        ("Response", view.response_text(), "http"),
        ("Reproduce", ev.get("curl", ""), "bash"),
    ):
        if body:
            out += [f"**{label}**", "", f"```{lang}", str(body), "```", ""]
    return out


def _ts():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def save_html(path=None):
    """Render the report and write it to disk, returning the Path written.

    `generate_html()` returns markup, not a location. Callers that want a file
    on disk - the agent and the MCP server both do - must go through here, or
    they end up handing ~40 KB of HTML around as though it were a filename.
    """
    html = generate_html()
    out = REPORTS_DIR / f"yeepforge_report_{_ts()}.html" if path is None else path
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


def run():
    print_banner("REPORT GENERATOR", "tmrswrr - Professional Pentest Report")

    findings = _sorted_findings()
    risk_score, risk_level = _overall_risk(findings)
    info(f"Findings: {len(findings)} | Risk: {risk_level} (CVSS {risk_score})")

    print(f"""
  {NEON_CYN}[1]{RST} HTML Report     {SOFT_WHITE}(professional - dark header, finding cards, CVSS){RST}
  {NEON_CYN}[2]{RST} Markdown Report
  {NEON_CYN}[3]{RST} JSON Report
  {NEON_CYN}[4]{RST} All formats
  {NEON_CYN}[5]{RST} Summary in terminal
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")
    ts = _ts()

    if c in ("1", "4"):
        html = generate_html()
        path = REPORTS_DIR / f"yeepforge_report_{ts}.html"
        path.write_text(html, encoding="utf-8")
        success(f"HTML Report → {path}")
        info(f"Open: firefox {path}")

    if c in ("2", "4"):
        md = generate_markdown()
        path = REPORTS_DIR / f"yeepforge_report_{ts}.md"
        path.write_text(md, encoding="utf-8")
        success(f"Markdown → {path}")

    if c in ("3", "4"):
        data = {
            "tool": "YeepForge", "version": VERSION,
            "target": SESSION.get("target_url"),
            "engagement": SESSION.get("engagement"),
            "generated": datetime.datetime.now().isoformat(),
            "risk": {"score": risk_score, "level": risk_level},
            "findings": _sorted_findings(),
            "stats": {s: sum(1 for f in findings if f.get("severity") == s)
                      for s in ["Critical","High","Medium","Low","Info"]},
        }
        path = REPORTS_DIR / f"yeepforge_report_{ts}.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        success(f"JSON → {path}")

    if c == "5":
        risk_score, risk_level = _overall_risk(findings)
        col = {"Critical": NEON_RED, "High": NEON_YEL, "Medium": NEON_CYN,
               "Low": NEON_GRN, "Info": DIM}.get(risk_level, "")
        print(f"\n  {col}{BOLD}Overall Risk: {risk_level} (CVSS {risk_score}){RST}\n")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            n = sum(1 for f in findings if f.get("severity") == sev)
            if n:
                c2 = {"Critical": NEON_RED, "High": NEON_YEL, "Medium": NEON_CYN,
                      "Low": NEON_GRN, "Info": DIM}.get(sev, "")
                print(f"  {c2}{BOLD}{sev:<10}{RST} {n}")
        print()
        for i, f in enumerate(findings[:10], 1):
            sev = f.get("severity", "Info")
            c2 = {"Critical": NEON_RED, "High": NEON_YEL, "Medium": NEON_CYN,
                  "Low": NEON_GRN, "Info": DIM}.get(sev, "")
            score, _ = _get_cvss(f.get("title", ""), f.get("severity", ""))
            cvss_str = f" [{score}]" if score else ""
            print(f"  {c2}[{sev}]{RST}{cvss_str} {f.get('title','?')[:60]}")
