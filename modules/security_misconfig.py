"""
modules/security_misconfig.py
tmrswrr - A05: Security Misconfiguration
HTTP headers, CORS, debug endpoints, default creds, cloud misconfig
"""
import os
import shutil

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    PURE_WHITE,
    RST,
    error,
    info,
    print_banner,
    prompt,
    run_and_print,
    run_cmd,
    section,
    success,
    warn,
)
from utils.http import get_client, looks_like_notfound, notfound_signature


def _out(name: str) -> str:
    d = str(OUTPUT_DIR)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target() -> str:
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL")
        SESSION["target_url"] = url
    return url


#: Reserved-for-documentation host used as the CORS probe origin. Sending
#: probes at a domain someone else owns (the previous 'evil.com') puts the
#: target's traffic in a stranger's logs.
CORS_CANARY = "yeepforge-canary.example.net"
CORS_CANARY_SUFFIX = ".example.net"


def header_analysis():
    section("HTTP SECURITY HEADER ANALYSIS")
    url = _target()

    security_headers = {
        "Strict-Transport-Security": ("High", "Enables HTTPS enforcement (HSTS)"),
        "Content-Security-Policy":   ("High", "Prevents XSS via content policy"),
        "X-Frame-Options":           ("Medium", "Prevents clickjacking"),
        "X-Content-Type-Options":    ("Medium", "Prevents MIME sniffing"),
        "Referrer-Policy":           ("Low", "Controls referrer header leakage"),
        "Permissions-Policy":        ("Low", "Controls browser feature permissions"),
        "X-XSS-Protection":          ("Info", "Legacy XSS filter (deprecated but informative)"),
        "Cache-Control":             ("Info", "Controls caching behavior"),
    }

    info_headers = {
        "Server":       "Reveals server software",
        "X-Powered-By": "Reveals backend technology",
        "X-AspNet-Version": "Reveals ASP.NET version",
        "X-AspNetMvc-Version": "Reveals MVC version",
    }

    client = get_client()
    resp = client.safe_get(url, timeout=15)
    if resp is None:
        error("Failed to retrieve headers")
        return

    # Headers of the *final* response. The previous check ran `curl -I -L` and
    # searched the concatenated output, so a header set only on an intermediate
    # redirect counted as present on the application itself.
    headers = resp.headers
    print(f"\n{NEON_CYN}Response headers ({resp.status_code}):{RST}")
    for key, value in headers.items():
        print(f"  {key}: {value}")
    print()

    info("Security header analysis:")
    for header, (severity, desc) in security_headers.items():
        if header in headers:
            success(f"{header:<35} ✓ Present")
        else:
            warn(f"{header:<35} ✗ MISSING  ({desc})")
            add_vuln(f"Missing Header: {header}", severity, "A05:2021",
                     f"{desc}. The header is absent from the response.", url,
                     evidence=resp.evidence, confidence="Confirmed", cwe="CWE-693")

    print()
    info("Information disclosure in headers:")
    for header, desc in info_headers.items():
        value = headers.get(header)
        if value:
            warn(f"{header}: {value}  ← {desc}")
            add_vuln(f"Information Disclosure: {header}", "Low", "A05:2021",
                     f"{desc} - {header}: {value}", url,
                     evidence=resp.evidence, confidence="Confirmed", cwe="CWE-200")


def cors_analysis():
    section("CORS MISCONFIGURATION")
    url = _target()

    host = url.split("//")[-1].split("/")[0]
    origins_to_test = [
        f"https://{CORS_CANARY}",
        f"https://{host}.{CORS_CANARY}",   # suffix-match bypass
        f"https://{host.split(':')[0]}{CORS_CANARY_SUFFIX}",  # prefix-match bypass
        "null",
    ]

    info("Testing CORS policy with various Origin headers...")
    print()

    client = get_client()
    for origin in origins_to_test:
        # CORS headers are frequently emitted only on GET, not HEAD, so the
        # previous `curl -I` probe missed real misconfigurations.
        resp = client.safe_get(url, headers={"Origin": origin}, timeout=10)
        if resp is None:
            print(f"  {DIM}[!] {origin} (request failed){RST}")
            continue

        acao = (resp.headers.get("Access-Control-Allow-Origin") or "").strip()
        if not acao:
            print(f"  {DIM}[-] No CORS headers for origin: {origin}{RST}")
            continue
        # Only the dedicated header counts as credentialed - the old check
        # searched the whole response for the words 'credentials' and 'true'.
        creds = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"

        if acao == "*":
            # Browsers refuse to send credentials to a wildcard origin, so this
            # is an exposure of public data, not an account-takeover primitive.
            warn("Wildcard CORS: Access-Control-Allow-Origin: *")
            add_vuln("CORS Wildcard", "Low" if not creds else "Medium", "A05:2021",
                     "Access-Control-Allow-Origin: * allows any origin to read responses "
                     "(browsers block credentialed requests to a wildcard origin)",
                     url, evidence=resp.evidence, confidence="Confirmed", cwe="CWE-942")
        elif acao == origin:
            severity = "Critical" if creds else "Medium"
            flag = " with Access-Control-Allow-Credentials: true" if creds else ""
            success(f"CORS reflects origin: {origin} → {acao}{flag}")
            add_vuln("CORS Misconfiguration", severity, "A05:2021",
                     f"The application reflects an arbitrary Origin ({origin}) back in "
                     f"Access-Control-Allow-Origin{flag}", url,
                     evidence=resp.evidence, confidence="Confirmed", cwe="CWE-942")
        else:
            print(f"  {DIM}[-] {origin} → ACAO: {acao}{RST}")


#: Endpoints whose exposure actually hands an attacker something. Everything
#: else on the probe list was previously reported as High as well, which buried
#: a leaked heap dump under a dozen /health findings.
_CRITICAL_ENDPOINTS = ("/actuator/heapdump", "/actuator/env", "/console",
                       "/__debug__/", "/phpinfo.php", "/info.php", "/env",
                       "/config", "/rails/info")
_MEDIUM_ENDPOINTS = ("/actuator", "/swagger", "/api-docs", "/openapi.json",
                     "/graphiql", "/debug", "/api/debug", "/trace",
                     "/actuator/beans", "/actuator/mappings", "/actuator/threaddump")


def _endpoint_severity(path: str) -> str:
    """Severity for an exposed endpoint, by what it actually leaks."""
    if path in _CRITICAL_ENDPOINTS:
        return "Critical" if path.endswith(("heapdump", "env", "console")) else "High"
    if path in _MEDIUM_ENDPOINTS:
        return "Medium"
    # /health, /status, /version, /metrics: usually intentional, still worth noting.
    return "Info"


def debug_endpoints():
    section("DEBUG & FRAMEWORK ENDPOINTS")
    url = _target()

    endpoints = [
        # Django/Flask/Python
        ("/debug",          "Debug page"),
        ("/__debug__/",     "Django Debug Toolbar"),
        ("/console",        "Werkzeug interactive console"),
        ("/api/debug",      "API debug endpoint"),
        # Spring Boot Actuator
        ("/actuator",       "Spring Actuator root"),
        ("/actuator/health","Spring health"),
        ("/actuator/env",   "Spring environment vars"),
        ("/actuator/beans", "Spring beans (lists all components)"),
        ("/actuator/heapdump","Spring heap dump"),
        ("/actuator/threaddump","Spring thread dump"),
        ("/actuator/metrics","Spring metrics"),
        ("/actuator/mappings","Spring URL mappings"),
        # Rails
        ("/rails/info",     "Rails info"),
        ("/rails/mailers",  "Rails mailers"),
        # Express/Node
        ("/api-docs",       "API docs"),
        ("/swagger",        "Swagger UI"),
        ("/swagger-ui",     "Swagger UI"),
        ("/swagger.json",   "Swagger JSON spec"),
        ("/openapi.json",   "OpenAPI spec"),
        ("/graphiql",       "GraphiQL IDE"),
        ("/graphql",        "GraphQL endpoint"),
        # PHP
        ("/phpinfo.php",    "phpinfo()"),
        ("/info.php",       "phpinfo()"),
        ("/test.php",       "PHP test file"),
        # Generic
        ("/status",         "Status page"),
        ("/health",         "Health check"),
        ("/metrics",        "Metrics"),
        ("/version",        "Version info"),
        ("/env",            "Environment vars"),
        ("/config",         "Config exposure"),
        ("/trace",          "HTTP trace"),
    ]

    info(f"Checking {len(endpoints)} debug/framework endpoints...")
    client = get_client()
    notfound = notfound_signature(client, url)
    if notfound and notfound[0] == 200:
        warn(f"Target answers missing paths with HTTP 200 ({notfound[1]} bytes) - filtering soft-404s")
    print()

    for path, desc in endpoints:
        resp = client.safe_get(url.rstrip("/") + path, timeout=5)
        if resp is None:
            print(f"  {DIM}[!] {path} (request failed){RST}")
            continue
        code = resp.status_code

        if code == 200 and not looks_like_notfound(resp, notfound):
            severity = _endpoint_severity(path)
            success(f"[{code}] {url}{path}  ← {desc} ({severity})")
            add_vuln(f"Exposed Debug Endpoint: {path}", severity, "A05:2021",
                     f"{desc} is reachable without authentication "
                     f"(HTTP {code}, {len(resp.text)} bytes)",
                     url.rstrip("/") + path, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-489")
        elif code in (301, 302, 307):
            info(f"[{code}] {url}{path}  (redirect)")
        elif code == 403:
            info(f"[403] {url}{path}  (forbidden but exists)")
        else:
            print(f"  {DIM}[{code}] {path}{RST}")


def default_credentials():
    section("DEFAULT CREDENTIALS CHECK")
    url = _target()

    common_defaults = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "admin123"),
        ("admin", "1234"),
        ("admin", ""),
        ("root",  "root"),
        ("root",  "toor"),
        ("test",  "test"),
        ("guest", "guest"),
        ("user",  "user"),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("admin", "changeme"),
        ("admin", "admin@123"),
        ("super", "super"),
    ]

    endpoint  = prompt("Login endpoint (e.g. /login or /admin)")
    user_param = prompt("Username field name")
    pass_param = prompt("Password field name")
    fail_str  = prompt("Text that appears on failed login")

    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""
    import urllib.parse

    info(f"Testing {len(common_defaults)} default credential pairs...")
    found = []

    for user, pwd in common_defaults:
        data = f"{user_param}={urllib.parse.quote(user)}&{pass_param}={urllib.parse.quote(pwd)}"
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{endpoint}" '
            f'-H "Content-Type: application/x-www-form-urlencoded" '
            f'{cookie_flag} -d "{data}" -L -m 10'
        )
        if fail_str and fail_str.lower() not in out.lower() and len(out) > 50:
            success(f"DEFAULT CREDS WORK: {user}:{pwd}")
            found.append(f"{user}:{pwd}")
            add_vuln("Default Credentials", "Critical", "A05:2021",
                     f"Login succeeds with {user}:{pwd}", url + endpoint)
        else:
            print(f"  {DIM}[-] {user}:{pwd}{RST}")

    if found:
        out_file = _out("default_creds_found.txt")
        with open(out_file, "w") as f:
            f.write("\n".join(found))
        success(f"Found credentials saved → {out_file}")


def ssl_tls_check():
    section("SSL/TLS CONFIGURATION")
    url = _target()

    if shutil.which("testssl"):
        out = _out("testssl.txt")
        host = url.split("//")[-1].split("/")[0]
        run_and_print(f"testssl.sh {host} | tee {out}", timeout=300)
    elif shutil.which("sslscan"):
        host = url.split("//")[-1].split("/")[0]
        out = _out("sslscan.txt")
        run_and_print(f"sslscan {host} | tee {out}")
    elif shutil.which("nmap"):
        host = url.split("//")[-1].split("/")[0]
        out = _out("nmap_ssl.txt")
        run_and_print(
            f"nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle "
            f"-p 443 {host} -oN {out}"
        )
    else:
        info("Manual SSL check commands:")
        host = url.split("//")[-1].split("/")[0]
        print(f"""
  {NEON_CYN}openssl s_client -connect {host}:443 2>/dev/null | head -30{RST}
  {NEON_CYN}curl -sv {url} 2>&1 | grep -E "SSL|TLS|cipher"{RST}
  {NEON_CYN}Install testssl: apt install testssl.sh{RST}
""")


def run():
    print_banner("SECURITY MISCONFIGURATION", "A05:2021 - OWASP Top 10 #5")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} HTTP Security Header Analysis
  {NEON_CYN}[2]{RST} CORS Misconfiguration
  {NEON_CYN}[3]{RST} Debug & Framework Endpoints
  {NEON_CYN}[4]{RST} Default Credentials Check
  {NEON_CYN}[5]{RST} SSL/TLS Configuration
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            header_analysis()
        elif c == "2":
            cors_analysis()
        elif c == "3":
            debug_endpoints()
        elif c == "4":
            default_credentials()
        elif c == "5":
            ssl_tls_check()
        save_session()
