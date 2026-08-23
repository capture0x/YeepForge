"""
modules/logging_failures.py
tmrswrr - A09: Security Logging & Monitoring Failures
Log injection, detection evasion, missing audit trails
"""
from config.settings import SESSION, add_vuln, save_session
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
    run_cmd,
    section,
    success,
    warn,
)


def _target() -> str:
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL")
        SESSION["target_url"] = url
    return url


def log_injection():
    section("LOG INJECTION TESTING")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Testing log injection via User-Agent, headers, and parameters")

    payloads = [
        "\\n\\nGET /admin HTTP/1.1\\n\\n",
        "\\r\\nLOGIN: admin:cracked",
        "127.0.0.1 - admin - [01/Jan/2026] GET /admin 200",
        "\\x00\\x00\\x00",
        "\n\nINFO: Successful admin login from 127.0.0.1",
        "\\u000aINFO: root logged in",
    ]

    for p in payloads:
        run_cmd(
            f'curl -sk -o /dev/null '
            f'-H "User-Agent: {p}" '
            f'{cookie_flag} {url} -m 5'
        )
        print(f"  {NEON_CYN}[→]{RST} Log injection via User-Agent: {p[:60]}")

    info("Log injection probes sent - check application logs if accessible")
    print(f"""
  {NEON_CYN}Log injection impact:{RST}
    - Fake log entries can mislead incident response
    - Log file may be parsed by SIEM, triggering false alerts
    - If logs are viewed in a browser: stored XSS via log injection
    - CRLF injection (\\r\\n) can split HTTP responses
""")


def logging_coverage():
    section("LOGGING COVERAGE ASSESSMENT")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}Events that SHOULD be logged (OWASP ASVS):{RST}

  Authentication:
    ✓ Failed login attempts (with username, IP, timestamp)
    ✓ Successful logins
    ✓ Password changes
    ✓ Account lockouts
    ✓ MFA failures

  Authorization:
    ✓ Access denied events
    ✓ Privilege escalation attempts
    ✓ IDOR/unauthorized resource access

  Input Validation:
    ✓ Input validation failures (SQLi, XSS payloads)
    ✓ Unexpected file types uploaded

  Business Logic:
    ✓ Unusual transaction amounts
    ✓ High-value actions (delete account, transfer funds)

  {NEON_CYN}Testing if failed logins are logged:{RST}
""")
    endpoint = prompt("Login endpoint (to generate failed login events)")
    if endpoint:
        data = "username=logging_test_user&password=logging_test_INVALID_PASS_12345"
        run_cmd(
            f'curl -sk -X POST "{url}{endpoint}" '
            f'-H "Content-Type: application/x-www-form-urlencoded" '
            f'{cookie_flag} -d "{data}" -m 10'
        )
        success("Failed login generated - check if it appears in accessible logs")
        info("Check: /logs/, /api/audit, /actuator/auditevents, admin panel")


def error_handling():
    section("ERROR HANDLING & STACK TRACE EXPOSURE")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Testing for verbose error messages that leak internal information...")

    error_probes = [
        ("/?debug=true",             "GET"),
        ("/?test=<>\"'",             "GET"),
        ("/nonexistent-page-xyz",     "GET"),
        ("/api/undefined-endpoint",   "GET"),
        ("/api/v1/test",             "DELETE"),
        ("/",                         "INVALID_METHOD"),
    ]

    for path, method in error_probes:
        if method in ("GET", "POST", "DELETE"):
            out, _, rc = run_cmd(
                f'curl -sk -X {method} "{url}{path}" {cookie_flag} -m 10'
            )
        else:
            out, _, rc = run_cmd(
                f'curl -sk -X {method} "{url}" {cookie_flag} -m 10'
            )

        if out:
            indicators = [
                "traceback", "stack trace", "exception", "at org.", "at com.",
                "at java.", "at sun.", "NullPointerException", "SQLException",
                "ParseError", "syntax error", "DEBUG", "File ", "line ",
                "at /home", "at /var", "usr/lib", "undefined method",
            ]
            for ind in indicators:
                if ind.lower() in out.lower():
                    warn(f"Stack trace/debug info exposed at {path} ({method}): {ind}")
                    add_vuln("Verbose Error Messages", "Medium", "A09:2021",
                             f"Stack trace visible at {path}", url + path)
                    print(f"  {NEON_YEL}Snippet: {out[:200]}{RST}")
                    break
            else:
                print(f"  {DIM}[-] {method} {path} - no obvious debug info{RST}")


def monitor_detection():
    section("DETECTION & ALERTING ASSESSMENT")
    print(f"""
  {NEON_CYN}Testing if security events trigger alerts:{RST}

  {NEON_GRN}Indicators of Good Monitoring:{RST}
    - Account lockout after N failed logins (usually 5-10)
    - CAPTCHA appears after failed login attempts
    - IP blocking / rate limiting active
    - Email/SMS alert on new device login
    - Admin alert on privilege escalation attempt

  {NEON_GRN}Indicators of Poor Monitoring:{RST}
    - Unlimited login attempts (no lockout)
    - No CAPTCHA or challenge
    - Same response time regardless of attack
    - No notification on password change
    - Direct SQL/command errors visible

  {NEON_CYN}How to test:{RST}
    1. Attempt 20+ failed logins - does account lock?
    2. Send clearly malicious payloads - any WAF response?
    3. Access 50+ pages rapidly - does IP get blocked?
    4. Try SQLi/XSS - does error message change?

  {NEON_CYN}OWASP AppSensor framework for detection:{RST}
    Request-level: too many 404s, input validation failures
    Application: too many login failures, rapid navigation
    User: access from new country, unusual hours
""")

    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""
    endpoint = prompt("Login endpoint (to test account lockout)")
    if endpoint:
        info("Sending 15 failed login attempts...")
        locked = False
        for i in range(15):
            data = f"username=admin&password=wrong_pass_{i}"
            out, _, _ = run_cmd(
                f'curl -sk -X POST "{url}{endpoint}" '
                f'-H "Content-Type: application/x-www-form-urlencoded" '
                f'{cookie_flag} -d "{data}" -m 10 -L'
            )
            if any(x in out.lower() for x in ["locked", "blocked", "too many", "temporarily"]):
                success(f"Account lockout triggered after {i+1} attempts!")
                locked = True
                break

        if not locked:
            warn("No account lockout after 15 attempts!")
            add_vuln("No Account Lockout", "Medium", "A09:2021",
                     "No lockout after 15 failed login attempts", url + endpoint)


def run():
    print_banner("SECURITY LOGGING & MONITORING FAILURES", "A09:2021 - OWASP Top 10 #9")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Log Injection Testing
  {NEON_CYN}[2]{RST} Logging Coverage Assessment
  {NEON_CYN}[3]{RST} Error Handling & Stack Trace Exposure
  {NEON_CYN}[4]{RST} Detection & Alerting Capability Check
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            log_injection()
        elif c == "2":
            logging_coverage()
        elif c == "3":
            error_handling()
        elif c == "4":
            monitor_detection()
        save_session()
