"""
modules/auto_scanner.py
tmrswrr - Automated Full Pentest Scanner
Orchestrates crawl → fingerprint → test all OWASP categories → report
One-click professional web application security assessment

This is the highest-request-volume module in YeepForge, so every probe goes
through utils.http: the engagement's rate limit, scope check and proxy apply to
all of it, and each finding carries the request/response pair that produced it.
"""
import json
import os
import re
import shutil
import time
import urllib.parse
from urllib.parse import urlparse

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    BOLD,
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    ask_int,
    info,
    print_banner,
    prompt,
    run_cmd,
    section,
    success,
    warn,
)
from utils.http import get_client, looks_like_notfound, notfound_signature
from utils.tools import tool_cmd


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def _finding(title, severity, owasp, url, detail="", response=None,
             confidence="Firm", cwe="") -> dict:
    """One finding, carrying the response that proves it."""
    return {
        "title": title, "severity": severity, "owasp": owasp, "url": url,
        "detail": detail, "confidence": confidence, "cwe": cwe,
        "evidence": getattr(response, "evidence", None),
    }


# ── Progress tracker ──────────────────────────────────────────────────────────
class ScanProgress:
    def __init__(self, total: int):
        self.total   = total
        self.done    = 0
        self.findings = 0
        self.current = ""
        self.start   = time.time()

    def step(self, label: str):
        self.done += 1
        self.current = label
        elapsed = time.time() - self.start
        pct = int(self.done / self.total * 100)
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  {NEON_GRN}[{bar}]{RST} {pct:3d}%  "
              f"{NEON_CYN}{label[:40]:<40}{RST}  "
              f"{SOFT_WHITE}{elapsed:.0f}s  {self.findings} findings{RST}",
              end="", flush=True)

    def finding(self):
        self.findings += 1

    def done_all(self):
        print()


# ── Quick test functions (no user input, fully automated) ─────────────────────
def _quick_headers(url: str) -> list[dict]:
    """Check security headers on a real GET.

    HEAD is not used: a fair number of stacks answer it from a different code
    path (or with 405) and drop the very headers being audited.
    """
    client = get_client()
    resp = client.safe_get(url)
    if resp is None:
        return []
    present = {k.lower() for k in resp.headers}
    required = {
        "strict-transport-security": ("Missing HSTS", "Medium", "A05:2021"),
        "content-security-policy":   ("Missing CSP", "Medium", "A05:2021"),
        "x-frame-options":           ("Missing X-Frame-Options", "Medium", "A05:2021"),
        "x-content-type-options":    ("Missing X-Content-Type-Options", "Low", "A05:2021"),
    }
    findings = []
    for header, (title, sev, owasp) in required.items():
        if header not in present:
            findings.append(_finding(title, sev, owasp, url,
                                     f"Response carries no {header} header.",
                                     resp, cwe="CWE-693"))

    server = resp.headers.get("Server", "").strip()
    # A bare product name ("nginx") tells an attacker nothing; a version does.
    if server and re.search(r"\d", server):
        findings.append(_finding(
            f"Server Header Disclosure: {server}", "Low", "A05:2021", url,
            f"Server header advertises a precise version: {server}",
            resp, cwe="CWE-200"))
    return findings


def _quick_sensitive_files(base_url: str) -> list[dict]:
    """Fast sensitive file probe, judged against the app's own missing-page.

    Status 200 alone is not exposure: an SPA answers every unknown path with
    index.html and 200, which used to make this function report all nineteen
    paths as critical findings on every single-page application.
    """
    client = get_client()
    signature = notfound_signature(client, base_url)
    if signature is None:
        warn("Could not fingerprint the 404 page - file probes skipped to avoid noise.")
        return []

    critical_paths = [
        "/.env", "/.git/config", "/backup.sql", "/wp-config.php",
        "/config.php", "/phpinfo.php", "/actuator/env", "/actuator/health",
        "/swagger.json", "/.htpasswd", "/server-status", "/debug",
        "/.git/HEAD", "/config.json", "/.env.local", "/api-docs",
        "/graphql", "/graphiql", "/.DS_Store",
    ]
    # A path only counts when its body also looks like the file we asked for.
    content_proof = {
        "/.env": ("=",), "/.env.local": ("=",),
        "/.git/config": ("[core]", "repositoryformatversion"),
        "/.git/HEAD": ("ref:",),
        "/wp-config.php": ("DB_NAME", "DB_PASSWORD"),
        "/config.php": ("<?php",),
        "/phpinfo.php": ("phpinfo", "PHP Version"),
        "/actuator/env": ("propertySources", "systemProperties"),
        "/swagger.json": ("swagger", "openapi", "paths"),
        "/api-docs": ("swagger", "openapi", "paths"),
        "/.htpasswd": (":",),
        "/server-status": ("Apache Server Status", "Server uptime"),
        "/.DS_Store": ("Bud1",),
        "/backup.sql": ("INSERT INTO", "CREATE TABLE"),
    }

    findings = []
    for path in critical_paths:
        resp = client.safe_get(base_url.rstrip("/") + path, timeout=8)
        if resp is None or resp.status_code != 200:
            continue
        if looks_like_notfound(resp, signature):
            continue

        markers = content_proof.get(path)
        body = resp.text[:4000]
        if markers and not any(m.lower() in body.lower() for m in markers):
            # Served 200 with a body unlike the file itself - a catch-all route.
            continue

        severity = "Critical" if any(x in path for x in (".env", ".git", "config", "sql")) else "High"
        findings.append(_finding(
            f"Sensitive File Exposed: {path}", severity, "A02:2021",
            base_url.rstrip("/") + path,
            f"Returned HTTP 200 with content unlike the application's 404 page "
            f"({len(resp.text)} bytes).",
            resp, confidence="Confirmed" if markers else "Firm", cwe="CWE-200"))
    return findings


def _param_urls(endpoint: dict, params: list[str], value: str) -> list[tuple[str, str]]:
    """(param, url) pairs with `value` substituted into each named parameter."""
    out = []
    for param in params:
        sep = "&" if "?" in endpoint["url"] else "?"
        out.append((param, f"{endpoint['url']}{sep}{param}={value}"))
    return out


def _quick_sqli(endpoint: dict) -> list[dict]:
    """Quick error-based SQLi probe on endpoint params."""
    if not endpoint.get("params"):
        return []
    client = get_client()
    findings = []
    indicators = ("sql syntax", "mysql_fetch", "ora-0", "sqlite3.",
                  "postgresql", "syntax error at or near",
                  "unclosed quotation mark", "odbc driver")
    payloads = ["'", "1' OR '1'='1"]

    for param in list(endpoint["params"].keys())[:3]:
        for p in payloads:
            enc = urllib.parse.quote(p)
            sep = "&" if "?" in endpoint["url"] else "?"
            test_url = f"{endpoint['url']}{sep}{param}={enc}"
            resp = client.safe_get(test_url, timeout=8)
            if resp is None:
                continue
            hit = next((i for i in indicators if i in resp.text.lower()), None)
            if hit:
                findings.append(_finding(
                    f"SQL Injection: {urlparse(endpoint['url']).path} ?{param}",
                    "Critical", "A03:2021", test_url,
                    f"Payload {p} in parameter '{param}' produced a database error "
                    f"('{hit}') in the response.",
                    resp, confidence="Confirmed", cwe="CWE-89"))
                break
    return findings


def _quick_xss(endpoint: dict) -> list[dict]:
    """Quick reflection probe.

    Reflection is reported as reflection, not as XSS: a canary echoed into a
    JSON body or a text/plain response is not exploitable, and marking it High
    is the fastest way to fill a report with findings a triager will close.
    """
    if not endpoint.get("params"):
        return []
    client = get_client()
    canary = "wsx<x>'\"12345"
    findings = []
    for param, test_url in _param_urls(
            endpoint, list(endpoint["params"].keys())[:3], urllib.parse.quote(canary)):
        resp = client.safe_get(test_url, timeout=8)
        if resp is None or canary not in resp.text:
            continue
        ctype = resp.headers.get("Content-Type", "")
        is_html = "html" in ctype.lower()
        findings.append(_finding(
            f"Reflected {'XSS' if is_html else 'Input (non-HTML context)'}: "
            f"{urlparse(endpoint['url']).path} ?{param}",
            "High" if is_html else "Low", "A03:2021", test_url,
            f"Parameter '{param}' is reflected with its angle brackets and quotes "
            f"intact in a {ctype or 'unknown'} response.",
            resp, confidence="Firm" if is_html else "Tentative", cwe="CWE-79"))
    return findings


def _quick_cors(url: str) -> list[dict]:
    """CORS misconfiguration check against a reflected malicious origin.

    Only a *reflected* origin combined with credentials is exploitable. A
    wildcard ACAO cannot carry credentials - browsers refuse the pair - so
    reporting `*` as Critical, as this check used to, is wrong.
    """
    client = get_client()
    evil = "https://evil.example"
    resp = client.safe_get(url, headers={"Origin": evil})
    if resp is None:
        return []
    acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
    if not acao:
        return []

    if acao == evil and acac == "true":
        return [_finding(
            "CORS Misconfiguration - Reflected Origin with Credentials",
            "High", "A05:2021", url,
            f"The response reflects an arbitrary Origin ({evil}) in "
            "Access-Control-Allow-Origin and sets Allow-Credentials: true, so any "
            "site can read authenticated responses from this endpoint.",
            resp, confidence="Confirmed", cwe="CWE-942")]
    if acao == evil:
        return [_finding(
            "CORS - Reflected Origin", "Medium", "A05:2021", url,
            f"An arbitrary Origin ({evil}) is reflected in "
            "Access-Control-Allow-Origin. Credentials are not allowed, so impact is "
            "limited to data the endpoint returns without a session.",
            resp, confidence="Firm", cwe="CWE-942")]
    if acao == "*":
        return [_finding(
            "CORS - Wildcard Origin", "Low", "A05:2021", url,
            "Access-Control-Allow-Origin is *. Credentialed requests are refused by "
            "browsers, so this only exposes data available without authentication.",
            resp, confidence="Firm", cwe="CWE-942")]
    return []


def _quick_ssrf(endpoint: dict) -> list[dict]:
    """SSRF probe on URL-like params, confirmed by metadata content."""
    url_params = [p for p in endpoint.get("params", {})
                  if any(x in p.lower() for x in
                         ("url", "redirect", "next", "src", "dest", "callback"))]
    if not url_params:
        return []
    client = get_client()
    internal = urllib.parse.quote("http://169.254.169.254/latest/meta-data/", safe="")
    findings = []
    for param, test_url in _param_urls(endpoint, url_params[:2], internal):
        resp = client.safe_get(test_url, timeout=10)
        if resp is None:
            continue
        body = resp.text.lower()
        if any(x in body for x in ("ami-id", "instance-id", "iam/", "local-ipv4")):
            findings.append(_finding(
                f"SSRF - AWS Metadata via {param}", "Critical", "A10:2021", test_url,
                f"Parameter '{param}' fetched http://169.254.169.254/latest/meta-data/ "
                "and returned EC2 instance metadata in the response.",
                resp, confidence="Confirmed", cwe="CWE-918"))
    return findings


def _quick_open_redirect(endpoint: dict) -> list[dict]:
    redirect_params = [p for p in endpoint.get("params", {})
                       if any(x in p.lower() for x in
                              ("redirect", "next", "url", "goto", "return", "target", "dest"))]
    if not redirect_params:
        return []
    client = get_client()
    evil = urllib.parse.quote("https://evil.example", safe="")
    findings = []
    for param, test_url in _param_urls(endpoint, redirect_params[:2], evil):
        resp = client.safe_get(test_url, timeout=8, allow_redirects=False)
        if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
            continue
        location = resp.headers.get("Location", "")
        # Only an off-site host counts. "/evil.example" or "https://app/?x=evil"
        # keeps the user on the application.
        host = urlparse(location).netloc.lower()
        if host and "evil.example" in host:
            findings.append(_finding(
                f"Open Redirect via {param}", "Medium", "A01:2021", test_url,
                f"Parameter '{param}' sends HTTP {resp.status_code} with "
                f"Location: {location} - an attacker-controlled host.",
                resp, confidence="Confirmed", cwe="CWE-601"))
    return findings


# ── Main scanner ──────────────────────────────────────────────────────────────
def full_scan():
    section("AUTOMATED FULL PENTEST SCAN")
    url = _target()

    warn("This will actively test the target for multiple vulnerability classes.")
    warn("Ensure you have written authorization before proceeding.")
    if prompt("Confirm authorization [yes/no]").lower() != "yes":
        info("Aborted.")
        return

    scan_id  = time.strftime("%Y%m%d_%H%M%S")
    out_dir  = _out(f"scan_{scan_id}")
    os.makedirs(out_dir, exist_ok=True)

    all_findings: list[dict] = []

    def record(findings_list):
        for f in findings_list:
            all_findings.append(f)
            add_vuln(f["title"], f["severity"], f.get("owasp", ""), f.get("detail", ""),
                     f.get("url", ""), evidence=f.get("evidence"),
                     confidence=f.get("confidence", "Firm"), cwe=f.get("cwe", ""))
            prog.finding()

    # ── Phase 1: Crawl ────────────────────────────────────────────────────────
    print(f"\n  {NEON_CYN}{BOLD}Phase 1/5 - Crawling target{RST}")
    crawl_result = None
    try:
        from modules.crawler import Crawler
        max_pages = ask_int("Max pages to crawl", 100, minimum=1)
        c = Crawler(url, max_depth=3, max_pages=max_pages)
        crawl_result = c.run()
        endpoints = crawl_result["endpoints"]
        SESSION["_crawl_results"] = crawl_result
        SESSION["endpoints"] = [ep["url"] for ep in endpoints]
        success(f"Crawled {len(endpoints)} endpoints, {len(crawl_result['js_files'])} JS files")
    except Exception as e:
        warn(f"Crawler error: {e} - using target URL only")
        endpoints = [{"url": url, "method": "GET", "params": {}, "forms": []}]

    # ── Phase 2: Passive checks ───────────────────────────────────────────────
    print(f"\n  {NEON_CYN}{BOLD}Phase 2/5 - Passive checks{RST}")
    total_steps = 6 + len(endpoints) * 4
    prog = ScanProgress(total_steps)

    prog.step("Security headers")
    record(_quick_headers(url))
    prog.step("Sensitive files")
    record(_quick_sensitive_files(url))
    prog.step("CORS")
    record(_quick_cors(url))

    prog.step("Tech fingerprint")
    fp = get_client().safe_get(url)
    if fp is not None:
        techs = [f"{name}: {fp.headers[name]}" for name in
                 ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")
                 if fp.headers.get(name)]
        if techs:
            info(f"Tech stack: {', '.join(techs)}")
            SESSION["tech_stack"] = techs

    # ── Phase 3: Active injection tests ──────────────────────────────────────
    print(f"\n\n  {NEON_CYN}{BOLD}Phase 3/5 - Active vulnerability tests{RST}")

    param_endpoints = [ep for ep in endpoints if ep.get("params") or ep.get("forms")]
    info(f"Testing {len(param_endpoints)} parameterized endpoints...")

    for ep in param_endpoints[:50]:  # Cap at 50 for speed
        parsed_path = urlparse(ep["url"]).path
        prog.step(f"SQLi: {parsed_path[-30:]}")
        record(_quick_sqli(ep))
        prog.step(f"XSS: {parsed_path[-30:]}")
        record(_quick_xss(ep))
        prog.step(f"SSRF: {parsed_path[-30:]}")
        record(_quick_ssrf(ep))
        prog.step(f"Redirect: {parsed_path[-30:]}")
        record(_quick_open_redirect(ep))

    prog.done_all()

    # ── Phase 4: Tools scan ───────────────────────────────────────────────────
    print(f"\n  {NEON_CYN}{BOLD}Phase 4/5 - Tool-based scan{RST}")
    if shutil.which("nikto"):
        info("Running nikto...")
        nikto_out = _out("nikto.txt")
        run_cmd(tool_cmd("nikto", ["-h", url, "-o", nikto_out,
                                   "-Format", "txt", "-nointeractive"]), timeout=180)
        success(f"nikto → {nikto_out}")
    else:
        info("nikto not found - skipping (apt install nikto)")

    if shutil.which("nuclei"):
        info("Running nuclei (critical/high templates)...")
        nuclei_out = _out("nuclei.txt")
        run_cmd(tool_cmd("nuclei", ["-u", url, "-severity", "critical,high",
                                    "-silent", "-o", nuclei_out]), timeout=300)
        # These go through record() so they reach the report; appending straight
        # to all_findings, as this used to, left every nuclei hit out of the HTML.
        record(_parse_nuclei(nuclei_out, url))
        success(f"nuclei → {nuclei_out}")
    else:
        info("nuclei not found - skipping (go install github.com/projectdiscovery/nuclei/...)")

    # ── Phase 5: Generate report ──────────────────────────────────────────────
    print(f"\n  {NEON_CYN}{BOLD}Phase 5/5 - Generating report{RST}")

    by_sev = {}
    for f in all_findings:
        s = f.get("severity", "Info")
        by_sev[s] = by_sev.get(s, 0) + 1

    print(f"\n  {NEON_GRN}{'═'*60}{RST}")
    print(f"  {BOLD}SCAN COMPLETE - {url}{RST}")
    print(f"  {NEON_GRN}{'═'*60}{RST}")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        n = by_sev.get(sev, 0)
        if n:
            colors = {"Critical": NEON_RED, "High": NEON_YEL,
                      "Medium": NEON_CYN, "Low": NEON_GRN, "Info": DIM}
            c = colors.get(sev, "")
            print(f"  {c}{BOLD}{sev:<10}{RST} {n}")
    print(f"  {SOFT_WHITE}Total: {len(all_findings)} findings{RST}")

    result = {
        "scan_id":   scan_id,
        "target":    url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        # Evidence objects are not JSON-serialisable and are already in the
        # session the HTML report reads.
        "findings":  [{k: v for k, v in f.items() if k != "evidence"}
                      for f in all_findings],
        "endpoints": len(endpoints),
        "summary":   by_sev,
    }
    json_file = os.path.join(out_dir, "scan_results.json")
    with open(json_file, "w") as f:
        json.dump(result, f, indent=2)
    success(f"Results → {json_file}")

    try:
        import modules.reporting as rep
        rep_path = _out(f"scan_{scan_id}/report.html")
        html = rep.generate_html()
        with open(rep_path, "w") as f:
            f.write(html)
        success(f"HTML Report → {rep_path}")
        info(f"Open: firefox {rep_path}")
    except Exception as e:
        warn(f"HTML report error: {e}")

    save_session()
    return result


def _parse_nuclei(path: str, url: str) -> list[dict]:
    """Turn nuclei's `[template] [proto] [severity] url [extra]` lines into findings."""
    if not os.path.exists(path):
        return []
    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium",
               "low": "Low", "info": "Info"}
    findings = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            tags = re.findall(r"\[([^\]]+)\]", line)
            if not tags:
                continue
            severity = next((sev_map[t.lower()] for t in tags
                             if t.lower() in sev_map), "Info")
            hit_url = next((w for w in line.split() if w.startswith("http")), url)
            findings.append(_finding(
                f"nuclei: {tags[0]}", severity, "A06:2021", hit_url,
                f"nuclei template `{tags[0]}` matched.\n\n{line}",
                confidence="Firm", cwe=""))
    return findings


def quick_check():
    """30-second passive check - headers, files, CORS."""
    section("QUICK PASSIVE CHECK (30s)")
    url = _target()

    info(f"Running passive checks on {url}...")
    findings = []
    findings += _quick_headers(url)
    findings += _quick_sensitive_files(url)
    findings += _quick_cors(url)

    if findings:
        print()
        for f in findings:
            colors = {"Critical": NEON_RED, "High": NEON_YEL, "Medium": NEON_CYN, "Low": NEON_GRN}
            c = colors.get(f["severity"], "")
            print(f"  {c}[{f['severity']}]{RST} {f['title']}")
            if f.get("url"):
                print(f"  {DIM}     → {f['url']}{RST}")
            add_vuln(f["title"], f["severity"], f.get("owasp", ""), f.get("detail", ""),
                     f.get("url", ""), evidence=f.get("evidence"),
                     confidence=f.get("confidence", "Firm"), cwe=f.get("cwe", ""))
    else:
        success("No obvious passive findings")

    save_session()


def run():
    print_banner("AUTO SCANNER", "tmrswrr - Automated Full Pentest Orchestrator")
    while True:
        url = SESSION.get("target_url", "-")
        findings_count = len(SESSION.get("vulns_found", []))
        print(f"""
  {NEON_GRN}Target:{RST}   {PURE_WHITE}{url}{RST}
  {NEON_GRN}Findings:{RST} {PURE_WHITE}{findings_count} recorded{RST}

  {NEON_CYN}[1]{RST} Full Automated Scan   {SOFT_WHITE}(crawl → OWASP tests → nikto → nuclei → report){RST}
  {NEON_CYN}[2]{RST} Quick Passive Check   {SOFT_WHITE}(30s - headers, files, CORS){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": full_scan()
        elif c == "2": quick_check()
        save_session()
